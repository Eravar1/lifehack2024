package ui

import (
	"log"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func Start() {
	mw, err := NewMainWindow()
	if err != nil {
		log.Fatal(err)
	}
	mw.Run()
}

func NewMainWindow() (*walk.MainWindow, error) {
	var mw *walk.MainWindow
	if err := (MainWindow{
		AssignTo: &mw,
		Title:    "Ransomware Detection App",
		Size:     Size{Width: 400, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{
				Text: "Welcome to the Ransomware Detection App!",
			},
		},
	}.Create()); err != nil {
		return nil, err
	}
	return mw, nil
}
