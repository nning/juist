# Building the Android app

You need JDK 21, the Android SDK with platform 37.2, and NDK 29. Set
`ANDROID_HOME` to the SDK, and `ANDROID_NDK_HOME` to the NDK if it is not
inside the SDK. Then, in the repository's root:

```sh
make android
```

This builds the core and the app into `android/app/build/outputs/apk`, a
release and a debug build for each processor architecture. A phone needs the
`arm64-v8a` build, the emulator the `x86_64` one. Install it on a phone
connected by USB, with USB debugging on:

```sh
adb install android/app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

Or copy the file to the phone and open it there.

## Signing

Android installs only signed apps. The release build is signed with your own
key. Create it once with the JDK's `keytool`:

```sh
keytool -genkeypair -keystore ~/juist-app.jks -alias juist -keyalg RSA -keysize 4096 -validity 10000
```

and enter it in `~/.gradle/gradle.properties`:

```text
juist.signing.store=/home/you/juist-app.jks
juist.signing.storePassword=…
juist.signing.keyAlias=juist
juist.signing.keyPassword=…
```

Instead of the two passwords, `juist.signing.passwordFile=` can name a file
holding the password. This works for a PKCS12 keystore, which `keytool`
creates by default.

Without these settings the release build stays unsigned. Install the debug
build instead, `apk/debug/app-arm64-v8a-debug.apk`. It is a separate app,
`io.juist.debug`, and installs next to a release build.

Android installs an update only if the same key signed both, so a release
does not install over an app you built yourself, or the other way round.
Uninstalling the app to switch deletes the phone's keys, and the phone has to
join again as a new device.
