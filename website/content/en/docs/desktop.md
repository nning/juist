---
title: The status bar on Linux
linkTitle: Status bar
description: See in a Linux desktop's status bar whether juist is connected, which exit node is in use and what needs attention, and switch the exit node from its menu.
lead: juist tray puts an icon in the status bar of a Linux desktop. It shows how juist stands at a glance, and its menu switches the exit node without a terminal.
---

## Turning it on

`juist tray` shows the icon, on Linux, for as long as your session runs. To
have it start with your desktop session from then on:

```sh
juist tray --autostart
```

This puts an entry in your own autostart directory
(`~/.config/autostart/juist-tray.desktop`) and starts nothing yet: run
`juist tray` once to see it now, or log in again. Each user turns it on for
themselves; on a server, nothing changes. To turn it off again:

```sh
juist tray --autostart=false
```

## Which desktops show it

The icon is a StatusNotifierItem, which KDE Plasma, Xfce, Cinnamon, LXQt and
sway's and waybar's bars show. GNOME shows it only with the AppIndicator
extension: install `gnome-shell-extension-appindicator` (Debian, Ubuntu and
Fedora), turn it on in the Extensions app, and log in again. Where no status
bar shows the icon ten seconds after it starts, juist tray says so in a
notification.

## The icon

| The icon | means |
|---|---|
| the juist logo, grey | juistd is not running, or this device is in no network or not connected |
| the juist logo | connected |
| with an arrow, top right | the internet goes through an exit node |
| with an amber dot, bottom right | `juist health` warns |
| with a red dot, bottom right | an alarm, as `juist status` shows it in red |

Pointing at the icon shows the first lines of `juist status`.

## The menu

- **This device** and its addresses. A click copies the name or the address;
  copying needs `wl-copy` (from wl-clipboard) on Wayland, or `xclip` or
  `xsel` on X11.
- **Devices**, those this device keeps a tunnel to, each with how the last
  check reached it. A click copies its address. `juist devices` lists them
  all.
- **Exit node**: none, or one of the devices granted the role. One that does
  not serve is greyed out. Choosing one runs `juist exit use` as you, with
  its checks; what it warns of, or why it refuses, comes as a notification.
- What `juist health` warns of, if anything.

On a device in [several networks]({{< relref "docs/networks" >}}), the menu has
one submenu per network. A warning from `juist health` that was not there
before, or an alarm, also comes as a notification.

## Who may switch

The device's [operator]({{< relref "docs/operator" >}}) gets the whole menu.
Every other user sees the state, without the devices and without the exit
node switch, as `juist status` shows it to them. To make yourself the
operator:

```sh
sudo juist set --operator=$USER
```

juist tray holds no keys. Inviting, approving and removing devices stay on
the command line.

## Good to know

- juist tray asks juistd for its state every few seconds, and runs
  `juist health` when it changes, otherwise once a minute.
- When juistd stops, the icon turns grey. It comes back when juistd starts
  again, without restarting juist tray.
- One juist tray runs per session; a second one stops at once.
- The desktop's own autostart settings list the entry too, and can turn it
  off there.
- Removing juist leaves the entry in your home directory; it starts nothing
  without juist.
