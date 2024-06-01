package util

import (
	"strings"
	"syscall"
	"unsafe"
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/windows"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW = kernel32.NewProc("CreateFileW")
	device       = "eth0" // Change to your network interface
	snapshotLen  = int32(1024)
	promiscuous  = false
	timeout      = pcap.BlockForever
	filter       = "ip and (dst net 0.0.0.0/0)" // Outbound traffic filter
	handle       *pcap.Handle
	err          error
	outboundData int
	protocolCounts   = make(map[string]int)
	failedConns      = make(map[string]int)
	anomalyThreshold = 1000
)

func CreateFile(name string, access, shareMode, creationDisposition, flagsAndAttributes uint32) (windows.Handle, error) {
	pName, err := syscall.UTF16FromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := procCreateFileW.Call(uintptr(unsafe.Pointer(&pName[0])), uintptr(access), uintptr(shareMode), 0, uintptr(creationDisposition), uintptr(flagsAndAttributes), 0)
	if handle == uintptr(windows.InvalidHandle) {
		return windows.InvalidHandle, err
	}
	return windows.Handle(handle), nil
}

func capturePackets() bool {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		outboundData += len(packet.Data())

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			key := net.JoinHostPort(packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort.String())

			if tcp.SYN && !tcp.ACK {
				failedConns[key]++
			}

			protocolCounts["TCP"]++
		}

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			protocolCounts["UDP"]++
		}
	}

	return checkNetworkAnomalies();
}

func checkNetworkAnomalies() bool {
	// Check for high volume of outbound traffic
	if outboundData > anomalyThreshold {
		log.Printf("High volume of outbound traffic detected: %d bytes", outboundData)
		return true
	}

	// Check for unusual protocols or ports
	for protocol, count := range protocolCounts {
		if count > anomalyThreshold {
			log.Printf("Unusual high count for protocol %s: %d", protocol, count)
			return true
		}
	}

	// Check for repeated failed connections
	for key, count := range failedConns {
		if count > 5 { // Example threshold for failed connections
			log.Printf("Repeated failed connections detected from %s: %d attempts", key, count)
			return true
		}
	}

	return false
}

func IsSuspiciousActivity(event fsnotify.Event) bool {
	// Initialize packet capture
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Start packet capture in a separate goroutine
	if (capturePackets() == bool) {
		if event.Op&fsnotify.Write == fsnotify.Write {
			if strings.HasSuffix(event.Name, ".locked") || strings.HasSuffix(event.Name, ".encrypted") || strings.HasSuffix(event.Name, ".crypt") {
				if event.Op&fsnotify.Rename == fsnotify.Rename {
					// the fsnotify package only provides the event for the new file, not the old filename
					// may need to maintain a map of files being monitored and their corresponding old names
					// Compare the old and new names to determine added characters
					// addedChars := getAddedCharacters(oldName, event.Name)
					// if len(addedChars) > 0 {
					// 	// Check with database if there are any other rename events with the added characters
					// 	return true
					// }
					return true
				}
			}
		}
	}
	
	return false
}

// getAddedCharacters returns the characters added to the filename during the rename
func getAddedCharacters(oldName, newName string) string {
	// Implement logic to find added characters
	oldNameLen := len(oldName)
	newNameLen := len(newName)

	if newNameLen > oldNameLen {
		return newName[oldNameLen:]
	}
	return ""
}