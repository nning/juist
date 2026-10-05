# The core's Go code calls into these by name through JNI.
-keep class go.** { *; }
-keep class io.juist.mobile.** { *; }
-keep class * implements io.juist.mobile.Platform { *; }
-keep class * implements io.juist.mobile.JoinListener { *; }
