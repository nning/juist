// Package sniprobe reads and clicks a status bar item over D-Bus, as a
// status bar does: StatusNotifierItem and its com.canonical.dbusmenu menu.
// Tests use it to see juist tray as a desktop shows it.
package sniprobe

import (
	"errors"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = "/StatusNotifierWatcher"
	itemIface   = "org.kde.StatusNotifierItem"
	menuIface   = "com.canonical.dbusmenu"
)

// An Item is one registered with the session's watcher.
type Item struct {
	conn *dbus.Conn
	dest string
	path dbus.ObjectPath
}

// Find is the item registered with the watcher whose Id is id.
func Find(conn *dbus.Conn, id string) (*Item, error) {
	v, err := conn.Object(watcherName, watcherPath).GetProperty(watcherName + ".RegisteredStatusNotifierItems")
	if err != nil {
		return nil, fmt.Errorf("asking the watcher: %w", err)
	}
	regs, _ := v.Value().([]string)
	for _, r := range regs {
		it := parse(conn, r)
		if got, err := it.prop("Id"); err == nil && got.Value() == id {
			return it, nil
		}
	}
	return nil, fmt.Errorf("no item %q among %q", id, regs)
}

// parse reads a registration: a bus name and a path, or either alone.
func parse(conn *dbus.Conn, r string) *Item {
	dest, path := r, "/StatusNotifierItem"
	if i := strings.Index(r, "/"); i >= 0 {
		dest, path = r[:i], r[i:]
	}
	return &Item{conn: conn, dest: dest, path: dbus.ObjectPath(path)}
}

func (it *Item) prop(name string) (dbus.Variant, error) {
	return it.conn.Object(it.dest, it.path).GetProperty(itemIface + "." + name)
}

// Title is the item's title.
func (it *Item) Title() (string, error) {
	v, err := it.prop("Title")
	if err != nil {
		return "", err
	}
	s, _ := v.Value().(string)
	return s, nil
}

// ToolTip is the title of the item's tooltip.
func (it *Item) ToolTip() (string, error) {
	v, err := it.prop("ToolTip")
	if err != nil {
		return "", err
	}
	var tip struct {
		Name  string
		Icons []struct {
			W, H int32
			Pix  []byte
		}
		Title, Text string
	}
	if err := dbus.Store([]any{v.Value()}, &tip); err != nil {
		return "", err
	}
	return tip.Title, nil
}

// Icon is the pixels of the item's first icon.
func (it *Item) Icon() ([]byte, error) {
	v, err := it.prop("IconPixmap")
	if err != nil {
		return nil, err
	}
	var px []struct {
		W, H int32
		Pix  []byte
	}
	if err := dbus.Store([]any{v.Value()}, &px); err != nil {
		return nil, err
	}
	if len(px) == 0 {
		return nil, errors.New("no icon")
	}
	return px[0].Pix, nil
}

// An Entry is one of the menu's.
type Entry struct {
	ID       int32
	Label    string
	Sep      bool
	Enabled  bool
	Toggle   bool
	Checked  bool
	Children []Entry
}

// Menu is the item's menu, whole.
func (it *Item) Menu() ([]Entry, error) {
	v, err := it.prop("Menu")
	if err != nil {
		return nil, err
	}
	path, _ := v.Value().(dbus.ObjectPath)
	var rev uint32
	var root []any
	obj := it.conn.Object(it.dest, path)
	// A menu may answer a first call one level deep.
	for range 2 {
		if err := obj.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
			return nil, err
		}
	}
	e, _, err := entry(root)
	return e.Children, err
}

// entry is a layout's entry, and whether it is visible.
func entry(fields []any) (Entry, bool, error) {
	if len(fields) != 3 {
		return Entry{}, false, fmt.Errorf("a menu layout of %d fields", len(fields))
	}
	id, _ := fields[0].(int32)
	props, _ := fields[1].(map[string]dbus.Variant)
	kids, _ := fields[2].([]dbus.Variant)
	e, visible := Entry{ID: id, Enabled: true}, true
	for k, v := range props {
		switch k {
		case "visible":
			visible, _ = v.Value().(bool)
		case "label":
			// "__" is a "_"; a lone one marks an access key, which no
			// label of a test has.
			e.Label, _ = v.Value().(string)
			e.Label = strings.ReplaceAll(e.Label, "__", "_")
		case "type":
			e.Sep = v.Value() == "separator"
		case "enabled":
			e.Enabled, _ = v.Value().(bool)
		case "toggle-type":
			e.Toggle = v.Value() == "checkmark"
		case "toggle-state":
			s, _ := v.Value().(int32)
			e.Checked = s == 1
		}
	}
	for _, k := range kids {
		f, _ := k.Value().([]any)
		c, shown, err := entry(f)
		if err != nil {
			return Entry{}, false, err
		}
		if shown {
			e.Children = append(e.Children, c)
		}
	}
	return e, visible, nil
}

// Click clicks the entry id.
func (it *Item) Click(id int32) error {
	v, err := it.prop("Menu")
	if err != nil {
		return err
	}
	path, _ := v.Value().(dbus.ObjectPath)
	return it.conn.Object(it.dest, path).Call(menuIface+".Event", 0, id, "clicked", dbus.MakeVariant(""), uint32(0)).Err
}

// Lookup is the first entry, depth first, labelled label.
func Lookup(entries []Entry, label string) (Entry, bool) {
	for _, e := range entries {
		if !e.Sep && e.Label == label {
			return e, true
		}
		if c, ok := Lookup(e.Children, label); ok {
			return c, true
		}
	}
	return Entry{}, false
}

// Format is entries one to a line, indented by depth: [x] for a checked
// entry, [ ] for one unchecked, and (off) after one disabled.
func Format(entries []Entry) string {
	var b strings.Builder
	var walk func([]Entry, string)
	walk = func(es []Entry, indent string) {
		for _, e := range es {
			if e.Sep {
				b.WriteString(indent + "---\n")
				continue
			}
			b.WriteString(indent)
			if e.Toggle {
				if e.Checked {
					b.WriteString("[x] ")
				} else {
					b.WriteString("[ ] ")
				}
			}
			b.WriteString(e.Label)
			if !e.Enabled {
				b.WriteString(" (off)")
			}
			b.WriteString("\n")
			walk(e.Children, indent+"  ")
		}
	}
	walk(entries, "")
	return b.String()
}
