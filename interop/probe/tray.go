package main

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/nning/juist/internal/sniprobe"
)

// tray reads juist tray's item on the session bus, as the status bar shows
// it: its title, its tooltip or its menu, or clicks an entry of the menu.
func tray(args []string) error {
	if len(args) < 1 || args[0] == "click" && len(args) != 2 {
		return errors.New("usage: probe tray title | tooltip | icon | menu | click LABEL")
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	it, err := sniprobe.Find(conn, "juist")
	if err != nil {
		return err
	}
	switch args[0] {
	case "title":
		s, err := it.Title()
		fmt.Println(s)
		return err
	case "tooltip":
		s, err := it.ToolTip()
		fmt.Println(s)
		return err
	case "icon":
		px, err := it.Icon()
		fmt.Printf("%x\n", sha256.Sum256(px))
		return err
	case "menu":
		m, err := it.Menu()
		fmt.Print(sniprobe.Format(m))
		return err
	case "click":
		m, err := it.Menu()
		if err != nil {
			return err
		}
		e, ok := sniprobe.Lookup(m, args[1])
		if !ok {
			return fmt.Errorf("no entry %q in\n%s", args[1], sniprobe.Format(m))
		}
		return it.Click(e.ID)
	}
	return fmt.Errorf("no tray command %q", args[0])
}
