---
title: Android
linkTitle: Android
description: Install juist's Android app, join a network with a phone by its QR code or code, reach the devices by name, and see from the phone how each one is reached.
lead: The Android app makes a phone a member of one network. It joins by the invite's QR code or code, reaches the other devices by their names and addresses, and shows how each of them is reached.
---

## What the app does

The app runs juist on a phone with Android 12 or newer. The phone joins one
network as a **member** with no roles, as a device that only reaches the
others and is reached by them. While its VPN is on, every app on the phone
reaches the other devices by their names, such as `nas.home.juist`, and at
their addresses in the network.

The VPN carries the traffic to the network's addresses, and the phone's DNS
([Names](#names)). The phone's other traffic bypasses juist, as before.

What the phone cannot do:

- It can be in only one network.
- It cannot turn [public names]({{< relref "docs/names" >}}) on, so a public
  name an admin points at a device resolves publicly there.
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
Start an invite in a terminal about 60 columns wide or wider, so that it can
show the QR code:

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

The app shows what `juist status`, `juist health` and `juist devices` show on
a computer (see
[Status and devices]({{< relref "docs/status" >}})):

- The network's name and state, such as **Connected**. Any other state comes
  with a line that explains it.
- Whatever needs attention, such as a device that does not answer, or
  **No device may relay**: a phone on mobile data often needs a
  [relay]({{< relref "docs/relays" >}}) to reach the others.
- This phone: its name, its DNS name, its IPv4 and IPv6 addresses (tap one to
  copy it), and its freshness, that is, when a voucher last confirmed that its view of the
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
runs an older juist; until that is updated, a ping gets through, other apps
do not).

Tap a device to see its name in DNS, its addresses, its roles and when it was
last heard from.
For a device reached through a relay, it names the device whose relay
carries the traffic.
**Ping** sends an echo through the tunnel. juist on that device answers it
itself, so the ping is answered even if the device's firewall drops pings.
**Open in browser** opens `http://` at its address. Every other app reaches the device
by the same name and addresses, such as an SSH client at `nas.home.juist`.

## Names

{{< screens >}}
status_private_dns: What the app says while Private DNS passes juist by
{{< /screens >}}

While the VPN is on, every lookup on the phone goes to juist, which runs in
the app. It answers the network's [names]({{< relref "docs/names" >}})
itself: each device as `nas.home.juist`, or just `nas`, and the names
[published]({{< relref "docs/publishing" >}}) under the network's domain,
those for members alone among them, which then lead straight to their
device through the tunnel. It also answers who an address of the network
is, so that an app looking up `198.18.36.2` learns `nas.home.juist` and
asks no one outside. Every other name it asks of the network the
phone is on, as the phone would without juist, and through DNS over TLS
where the phone's Private DNS, set to automatic, does that too.

The status screen shows the phone's own name under **DNS name**, and each
device's screen its name. A lookup juist cannot pass on, as with no network
or through an exit node that cannot be used, fails at once rather than
after a few seconds. Turning the VPN off gives the
phone its own DNS back.

Android's **Private DNS** setting decides whether lookups reach juist:

| Private DNS | Names |
|---|---|
| Off | resolved |
| Automatic | resolved |
| Private DNS provider hostname | not resolved: Android sends every lookup to that provider, past juist |

With a provider's hostname set, juist leaves the phone's DNS alone, and the
app says that the network's names are not resolved, and names each name for
members alone that is then out of reach.

## Through an exit node

Where the network has [exit nodes]({{< relref "docs/exit-nodes" >}}), the
status screen lists them under **Internet**, beside **Direct**. Choose one,
and the phone's internet and its DNS go through it, as `juist exit use`
does on a computer. juist still answers the network's names itself. While the chosen exit node cannot be used, the phone's
internet traffic is blocked rather than sent around it, and the app says why.
Choose **Direct** to send it out without juist again.

If juist stops, Android sends the phone's traffic directly. To block it
instead, turn on **Always-on VPN** and **Block connections without VPN** for
juist in Android's VPN settings. The app links to them.

## Turning the VPN off and on

The switch beside the state turns the VPN off and on. While it is on, a
notification shows the state, with a **Turn off** action.

If the VPN was on, juist turns it on again after the phone restarts or the
app is updated. Android's own setting **Always-on VPN**, under the VPN
settings, works with juist too. Android runs only one VPN at a time: another
VPN app turns juist off, and the app tells you so.

## Battery

juist saves battery while the screen is off, the phone dozes or battery
saver is on. On a metered network, such as mobile data or a hotspot, it
also saves battery whenever the app is not in front. It then:

- checks the other members every 5 minutes instead of every 30 seconds,
  mostly with a single ping that wakes nothing else;
- syncs the network's log every 30 minutes instead of every 2;
- no longer pings idle members just to keep the paths to them open;
- stops listening and announcing itself on the Wi-Fi's multicast DNS, which
  would wake the phone for every such packet.

Changes to the network still arrive at once, and traffic through the tunnel
is not slowed down. If battery saver is on while the screen is on, the
status screen says so.

The phone searches the public DHT for members only while it reaches no
device other than phones. Any other member it reaches finds the others there
and passes them on.

The phone passes on nothing it hears from other devices; they do that among
themselves. News of its own it tells two other devices, which pass it on.
Once the network runs the app's schema, a sync exchanges only what the other
side lacks, rather than every device's details each time.

Once the network runs the app's schema
([Updating juist]({{< relref "docs/updating" >}})), the other devices let
the phone sleep too. They leave the log sync to the phone and check on it
every 30 minutes. Where no relay can reach the phone, they send it a single
ping every minute to keep the way to it open. A member still reaches a phone
whose screen is off at once: through a relay if there is one, otherwise
along the path those pings keep open.

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
| **Private DNS sends every lookup to …** | Set Private DNS to automatic or off in the phone's network settings. |
| `nas.home.juist` does not resolve | Turn the VPN on. Otherwise the status screen says why. |
