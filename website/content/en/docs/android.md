---
title: Android
linkTitle: Android
description: Build juist's Android app, join a network with a phone by its QR code or code, and see from the phone how each device is reached.
lead: The Android app makes a phone a member of one network. It joins by the invite's QR code or code, reaches the other devices at their addresses, and shows how each of them is reached.
---

## What it is

The app runs juist on a phone with Android 12 or newer. The phone joins one
network as a **member** with no roles, as a device that only reaches the
others and is reached by them. While its VPN is on, every app on the phone
reaches the other devices at their addresses in the network.

The VPN carries the network's addresses alone. The phone's other traffic and
its DNS go on as before, past juist.

What the phone does not do:

- It is in one network only.
- It resolves no names: `nas.home.juist` does not work there, so use the
  device's address, such as `198.18.36.2`.
- It uses no [subnet router]({{< relref "docs/subnets" >}}), and serves as
  no [exit node]({{< relref "docs/exit-nodes" >}}), though it can send its
  internet through one.
- It cannot invite, holds no admin key, and relays for nobody. An admin runs
  `juist invite` on a computer.

## Building and installing

You build the app from the source, on a computer with a JDK 21, the Android
SDK with platform 37.2, and NDK 29. Point `ANDROID_HOME` at the SDK, and
`ANDROID_NDK_HOME` at the NDK where it is not inside the SDK.

{{< step on="your computer" >}}
In the source, build the app:

```sh
make android
```

This builds the core and the app, a release and a debug build for each kind
of processor, into `android/app/build/outputs/apk`. A phone takes the
`arm64-v8a` one, the emulator the `x86_64` one.
{{< /step >}}
{{< step on="your computer" >}}
Install it on a phone connected by USB, with USB debugging on:

```sh
adb install android/app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

Or copy the file to the phone and open it there. Android then asks you to
let the app that opens it install apps.
{{< /step >}}

Android installs only a signed app. The release build is signed with a key of
your own, which you create once with the JDK's `keytool` and name in
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

Without them the release build stays unsigned. Install the debug build then,
`apk/debug/app-arm64-v8a-debug.apk`, which is an app of its own beside a
release build, `io.juist.debug`.

An update installs over the app only when the same key signed it. Keep the
key: uninstalling the app, to install one signed with another, deletes the
phone's keys, and it has to join again as a new device.

## Joining

{{< screens >}}
welcome: The first screen: scan the QR code, or type the code
joining_words: The four words, for the admin to compare
{{< /screens >}}

{{< step on="an admin's device" >}}
Start an invite, in a terminal at least 59 columns wide, so that it shows the
QR code:

```sh
juist invite
```
{{< /step >}}
{{< step on="the phone" >}}
Open juist and tap **Scan QR code**, then point the camera at the QR code.
Android asks once to let juist use the camera.

Or tap **Type code** and type the code, such as
`42-drumbeat-tolerance-glucose`; the app completes each word as you type it.
A code works only where the phone is on the same LAN as the inviting device,
since it finds that device by asking the LAN, as `juist join` does. Away from
it, scan the QR code, or paste the link into the same field.
{{< /step >}}
{{< step on="the phone" >}}
Check the name the network will list the phone by. The app suggests one from
the phone's own name, such as `pixel-8`. Tap **Join**, and allow the VPN
when Android asks.

The phone then shows four words in large type.
{{< /step >}}
{{< step on="an admin's device" >}}
Compare them with the words the invite shows, and answer `y` if they are the
same. If they differ, answer `n`, and cancel on the phone.
{{< /step >}}

Where the network needs more than one admin's vote, the phone shows
`Waiting for approval: 1 of 2 votes` until the others have approved. Then it
shows its status. [Inviting devices]({{< relref "docs/invites" >}}) explains
the code, the link and the words.

## The status screen

{{< screens >}}
status: The network, this phone and what needs attention
member: One device, with a ping through the tunnel
{{< /screens >}}

The app shows what `juist status` shows on a computer (see
[Status and devices]({{< relref "docs/status" >}})):

- The network's name and its state, such as **Connected**, with a line
  that explains any state other than that.
- Whatever needs attention, such as a device that does not answer, or
  **No device may relay**: a phone on mobile data often needs a
  [relay]({{< relref "docs/relays" >}}) to reach the others.
- This phone: its name, its IPv4 and IPv6 address, which you tap to copy, and
  its freshness, when a voucher last confirmed that its view of the network
  is current.
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
**Offline**, **Not heard from**, or **Not checked yet**.

Tap a device to see its addresses, its roles and when it was last heard from.
**Ping** sends an echo through the tunnel, which juist on that device answers
itself, so it is answered even where the device's firewall drops pings. **Open in
browser** opens `http://` at its address. Every other app reaches the device
at the same addresses, such as an SSH client at `198.18.36.2`.

## Through an exit node

Where the network has [exit nodes]({{< relref "docs/exit-nodes" >}}), the
status screen lists them under **Internet**, beside **Direct**. Choose one,
and the phone's internet and its DNS go through it, as `juist exit use`
does on a computer. While the chosen exit node cannot be used, the phone's
internet is refused rather than sent around it, and the app says why; choose
**Direct** to send it out without juist again.

If juist stops, Android sends the phone's traffic directly. To have it
blocked instead, turn on **Always-on VPN** and **Block connections without
VPN** for juist in Android's VPN settings, which the app links to.

## Turning it off and on

The switch beside the state turns the VPN off and on. While it is on, a
notification says how many devices the phone reaches, with a **Turn off**
action.

If the VPN was on, juist turns it on again after the phone restarts or the
app is updated. Android's own setting **Always-on VPN**, under the VPN
settings, works with juist too. Android runs one VPN at a time: another VPN
app turns juist off, and the app says so.

## When the phone is removed

An admin removes the phone like any device, with `juist remove pixel-8`
([Removing a device]({{< relref "docs/remove" >}})). The app then shows
**Removed**. Tap **Forget network** to start afresh, with new keys, and
join again with a new invite.

To stop using juist on the phone, have an admin remove it first, then
uninstall the app. The network keeps listing a phone that was only
uninstalled.

## Privacy and security

- The phone's keys are sealed by an AES-256 key that Android Keystore holds,
  in the phone's security chip where it has one. That key never leaves
  Keystore, so a copy of the app's files opens on no other phone.
- Nothing of juist goes into a backup or onto a new phone. A new phone
  joins with an invite of its own.
- The camera is used only on the scan screen, to read the QR code, and
  nothing it sees is stored or sent.
- **About**, in the menu, shows the app's version and the licenses of what it
  contains. **Copy log** copies the app's log, which it keeps in memory only.
  The log names your network's devices and addresses; share it only with
  someone you trust to help.

## If something goes wrong

| What you see | What to do |
|---|---|
| **Not joined** | The invite may have expired or been used, or the inviting device is out of reach. Start a new invite. A code works only on the same LAN; scan the QR code instead. |
| **No device may relay** | An admin grants `relay` to a device with a public address ([Relays]({{< relref "docs/relays" >}})). |
| **Limited** | Too few vouchers have been reached for 48 hours. Connect the phone to a network where it reaches them. |
| **Too few vouchers have vouched: limited in … hours** | Bring a voucher back online before then. |
| **Refused** or **Removed** | The phone was removed. Forget the network and join again with a new invite. |
| `nas.home.juist` does not resolve | The phone resolves no names; use the address the device's screen shows. |
