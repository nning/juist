---
title: Android
linkTitle: Android
description: Install juist's Android app, join a network with a phone by its QR code or code, and see from the phone how each device is reached.
lead: The Android app makes a phone a member of one network. It joins by the invite's QR code or code, reaches the other devices at their addresses, and shows how each of them is reached.
---

## What the app does

The app runs juist on a phone with Android 12 or newer. The phone joins one
network as a **member** with no roles, as a device that only reaches the
others and is reached by them. While its VPN is on, every app on the phone
reaches the other devices at their addresses in the network.

The VPN carries only traffic to the network's addresses. The phone's other
traffic and its DNS bypass juist, as before.

What the phone cannot do:

- It can be in only one network.
- It resolves no names: `nas.home.juist` does not work there, so use the
  device's address, such as `198.18.36.2`.
- It cannot use a [subnet router]({{< relref "docs/subnets" >}}) or act as an
  [exit node]({{< relref "docs/exit-nodes" >}}), though it can send its
  internet traffic through one.
- It cannot invite devices, hold an admin key, or relay for other devices.
  Invites come from an admin running `juist invite` on a computer.

## Installing the app

Every [release](https://github.com/nning/juist/releases/latest) has the app
as `juist-android-arm64.apk`. Download it on the phone and open it; Android
asks you to allow the browser to install apps. For the emulator, use
`juist-android-x86_64.apk`.

The app is signed with juist's release key. Its certificate has the SHA-256
fingerprint

```text
51:5C:14:80:41:8A:98:4A:8B:1A:E3:69:51:7A:2C:9F:7F:48:A2:19:41:0C:AE:E6:6F:B5:82:EF:EC:AB:E5:21
```

`apksigner verify --print-certs juist-android-arm64.apk` shows it. The APK is
also listed in `SHA256SUMS`, so you can check it as described in
[Verifying a download]({{< relref "docs/install" >}}#verifying-a-download).

## Building from source

You can also build the app yourself, on a computer with JDK 21, the Android
SDK with platform 37.2, and NDK 29. Set `ANDROID_HOME` to the SDK, and
`ANDROID_NDK_HOME` to the NDK if it is not inside the SDK.

{{< step on="your computer" >}}
In the source, build the app:

```sh
make android
```

This builds the core and the app into `android/app/build/outputs/apk`, with a
release and a debug build for each processor architecture. A phone needs the
`arm64-v8a` build, the emulator the `x86_64` one.
{{< /step >}}
{{< step on="your computer" >}}
Install it on a phone connected by USB, with USB debugging on:

```sh
adb install android/app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

Or copy the file to the phone and open it there. Android then asks you to
allow the app you opened it with to install apps.
{{< /step >}}

Android installs only signed apps. The release build is signed with your own
key, which you create once with the JDK's `keytool` and enter in
`~/.gradle/gradle.properties`:

```sh
keytool -genkeypair -keystore ~/juist-app.jks -alias juist -keyalg RSA -keysize 4096 -validity 10000
```

```text
juist.signing.store=/home/you/juist-app.jks
juist.signing.storePassword=…
juist.signing.keyAlias=juist
juist.signing.keyPassword=…
```

Instead of the two passwords, you can set `juist.signing.passwordFile=` to a
file holding the password. This works for a PKCS12 keystore, which has a
single password and is what `keytool` creates by default.

Without these settings the release build stays unsigned. Install the debug
build instead, `apk/debug/app-arm64-v8a-debug.apk`. It is a separate app,
`io.juist.debug`, and installs next to a release build.

Android installs an update over the app only if the same key signed both. So
a release does not install over an app you built yourself, or the other way
round. Stick with one: uninstalling the app to install one signed with a
different key deletes the phone's keys, and the phone has to join again as a
new device.

## Joining a network

{{< screens >}}
welcome: The first screen: scan the QR code, or type the code
joining_words: The four words, for the admin to compare
{{< /screens >}}

{{< step on="an admin's device" >}}
Start an invite in a terminal at least 59 columns wide, so that it can show
the QR code:

```sh
juist invite
```
{{< /step >}}
{{< step on="the phone" >}}
Open juist and tap **Scan QR code**, then point the camera at the QR code.
Android asks once to let juist use the camera.

Or tap **Type code** and type the code, such as
`42-drumbeat-tolerance-glucose`; the app completes each word as you type it.
A code works only if the phone is on the same LAN as the inviting device,
because the app finds that device by asking on the LAN, as `juist join` does.
Elsewhere, scan the QR code or paste the link into the same field.
{{< /step >}}
{{< step on="the phone" >}}
Check the name the phone will have in the network. The app suggests one based
on the phone's name, such as `pixel-8`. Tap **Join**, and allow the VPN
when Android asks.

The phone then shows four words in large type.
{{< /step >}}
{{< step on="an admin's device" >}}
Compare them with the words the invite shows, and answer `y` if they are the
same. If they differ, answer `n`, and cancel on the phone.
{{< /step >}}

If the network needs votes from more than one admin, the phone shows
`Waiting for approval: 1 of 2 votes` until the others have approved. Then it
shows its status. [Inviting devices]({{< relref "docs/invites" >}}) explains
the code, the link and the words.

## The status screen

{{< screens >}}
status: The network, this phone and what needs attention
member: One device, with a ping through the tunnel
{{< /screens >}}

The app shows what `juist status` and `juist devices` show on a computer (see
[Status and devices]({{< relref "docs/status" >}})):

- The network's name and state, such as **Connected**. Any other state comes
  with a line that explains it.
- Whatever needs attention, such as a device that does not answer, or
  **No device may relay**: a phone on mobile data often needs a
  [relay]({{< relref "docs/relays" >}}) to reach the others.
- This phone: its name, its IPv4 and IPv6 addresses (tap one to copy it), and
  its freshness, that is, when a voucher last confirmed that its view of the
  network is current.
- Each other device, with how it is reached.

| State | Meaning |
|---|---|
| Connected | the phone reaches the network's devices |
| Waiting for devices | there are other devices, but none has been heard from yet |
| No tunnel up | the devices are known, but no traffic flows to any of them |
| Limited | no voucher has confirmed lately that the phone's view is current, so it reaches only vouchers |
| Removed | the phone is no longer in the network |
| Refused | the network's devices refuse the phone; most likely it was removed |
| Disconnected | the network's history has split, and every tunnel is down until an admin resolves it |
| Off | the VPN is off |

A device is reached **Direct**, **Through a relay**, or not at the moment:
**No answer**, **Searching** (it may have restarted or changed networks),
**Offline**, **Not heard from**, **Not checked yet**, or **Outdated** (it
runs an older juist, and is unreachable until that is updated).

Tap a device to see its addresses, its roles and when it was last heard from.
**Ping** sends an echo through the tunnel. juist on that device answers it
itself, so the ping is answered even if the device's firewall drops pings.
**Open in browser** opens `http://` at its address. Every other app reaches the device
at the same addresses, such as an SSH client at `198.18.36.2`.

## Through an exit node

Where the network has [exit nodes]({{< relref "docs/exit-nodes" >}}), the
status screen lists them under **Internet**, beside **Direct**. Choose one,
and the phone's internet and its DNS go through it, as `juist exit use`
does on a computer. While the chosen exit node cannot be used, the phone's
internet traffic is blocked rather than sent around it, and the app says why.
Choose **Direct** to send it out without juist again.

If juist stops, Android sends the phone's traffic directly. To block it
instead, turn on **Always-on VPN** and **Block connections without VPN** for
juist in Android's VPN settings. The app links to them.

## Turning the VPN off and on

The switch beside the state turns the VPN off and on. While it is on, a
notification says how many devices the phone reaches, with a **Turn off**
action.

If the VPN was on, juist turns it on again after the phone restarts or the
app is updated. Android's own setting **Always-on VPN**, under the VPN
settings, works with juist too. Android runs only one VPN at a time: another
VPN app turns juist off, and the app tells you so.

## When the phone is removed

An admin removes the phone like any device, with `juist remove pixel-8`
([Removing a device]({{< relref "docs/remove" >}})). The app then shows
**Removed**. Tap **Forget network** to start over with new keys, then
join again with a new invite.

To stop using juist on the phone, have an admin remove it first, then
uninstall the app. The network keeps listing a phone that was only
uninstalled.

## Privacy and security

- The phone's keys are sealed by an AES-256 key that Android Keystore holds,
  in the phone's security chip if it has one. That key never leaves
  Keystore, so a copy of the app's files cannot be opened on another phone.
- Nothing of juist goes into a backup or onto a new phone. A new phone
  joins with its own invite.
- The camera is used only on the scan screen, to read the QR code, and
  nothing it sees is stored or sent.
- **About**, in the menu, shows the app's version and the licenses of what it
  contains. **Copy log** copies the app's log, which it keeps in memory only.
  The log names your network's devices and addresses; share it only with
  someone you trust to help you.

## Troubleshooting

| What you see | What to do |
|---|---|
| **Not joined** | The invite may have expired or been used, or the inviting device is out of reach. Start a new invite. A code works only on the same LAN; scan the QR code instead. |
| **No device may relay** | An admin grants `relay` to a device with a public address ([Relays]({{< relref "docs/relays" >}})). |
| **Limited** | The phone has not reached enough vouchers for 48 hours. Connect it to a network where it can reach them. |
| **Too few vouchers have vouched: limited in … hours** | Bring a voucher back online before then. |
| **Refused** or **Removed** | The phone was removed. Forget the network and join again with a new invite. |
| `nas.home.juist` does not resolve | The phone resolves no names; use the address the device's screen shows. |
