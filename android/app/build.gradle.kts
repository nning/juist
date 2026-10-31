import groovy.json.JsonSlurper

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.roborazzi)
}

// The repository's root, which holds the core's AAR and the design tokens.
val repo: Directory = rootProject.layout.projectDirectory.dir("..")

// The commit, not the clock, numbers a build, so two builds of one commit match
// and a later commit upgrades an earlier one; its name is `juist version`'s.
fun output(vararg args: String): String =
    providers.exec { commandLine(*args) }.standardOutput.asText.get().trim()

val commitTime = output("git", "log", "-1", "--format=%ct").toLong()
val versionLabel = output("sh", repo.file("packaging/version.sh").asFile.path, "android")

android {
    namespace = "io.juist.app"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "io.juist"
        minSdk = 31
        targetSdk = 36
        versionCode = ((commitTime - 1_767_225_600) / 60).toInt() // minutes since 2026
        versionName = versionLabel
        resourceConfigurations += listOf("en", "de")
    }

    signingConfigs {
        // A key of one's own signs the release build where these are given, as
        // -P or in ~/.gradle/gradle.properties; passwordFile holds the one
        // password of a PKCS12 store, or both passwords are given inline.
        val store = providers.gradleProperty("juist.signing.store").orNull
        if (store != null) {
            val password = providers.gradleProperty("juist.signing.passwordFile").orNull
                ?.let { file(it).readText().trim() }
            create("release") {
                storeFile = file(store)
                storePassword = password ?: providers.gradleProperty("juist.signing.storePassword").get()
                keyAlias = providers.gradleProperty("juist.signing.keyAlias").get()
                keyPassword = password ?: providers.gradleProperty("juist.signing.keyPassword").get()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }

    // A phone's APK carries its own ABI's core alone; the emulator's is x86_64.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    sourceSets["main"].assets.directories += repo.dir("build/android/assets").asFile.path
}

kotlin {
    jvmToolchain(21)
}

roborazzi {
    outputDir.set(layout.projectDirectory.dir("screenshots"))
}

tasks.withType<Test>().configureEach {
    // CoreTest and VpnConfigTest read what the Go side's tests write.
    inputs.file(repo.file("mobile/testdata/view.json"))
    inputs.file(repo.file("mobile/testdata/establish.json"))
    maxHeapSize = "3g"
    // Robolectric sets up shared memory through FileDescriptor's internals.
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED", "--add-exports=java.base/jdk.internal.access=ALL-UNNAMED")
}

// GenerateTokens writes design/tokens.json, which the website shares, as Kotlin.
abstract class GenerateTokens : DefaultTask() {
    @get:InputFile
    abstract val tokens: RegularFileProperty

    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @TaskAction
    fun generate() {
        @Suppress("UNCHECKED_CAST")
        val json = JsonSlurper().parse(tokens.get().asFile) as Map<String, Map<String, Any>>
        fun color(hex: Any) = "Color(0xFF${(hex as String).removePrefix("#").uppercase()})"
        fun palette(name: String, colors: Map<*, *>) =
            "internal val $name = Palette(\n" +
                colors.entries.joinToString(",\n") { "    ${it.key} = ${color(it.value!!)}" } + ",\n)\n"
        val color = json["color"]!!
        val status = json["status"]!!
        val roles = (color["day"] as Map<*, *>).keys
        val statuses = (status["day"] as Map<*, *>).keys
        val out = StringBuilder()
        out.append("// Generated from design/tokens.json by :app:generateTokens; do not edit.\n")
        out.append("package io.juist.app.ui.theme\n\nimport androidx.compose.ui.graphics.Color\n\n")
        out.append("internal class Palette(\n")
        roles.forEach { out.append("    val $it: Color,\n") }
        out.append(")\n\n")
        out.append(palette("DayPalette", color["day"] as Map<*, *>)).append('\n')
        out.append(palette("NightPalette", color["night"] as Map<*, *>)).append('\n')
        out.append("internal class StatusPalette(\n")
        statuses.forEach { out.append("    val $it: Color,\n") }
        out.append(")\n\n")
        listOf("day" to "DayStatus", "night" to "NightStatus").forEach { (k, n) ->
            out.append("internal val $n = StatusPalette(\n")
            (status[k] as Map<*, *>).forEach { (s, v) -> out.append("    $s = ${color(v!!)},\n") }
            out.append(")\n\n")
        }
        val dir = output.get().dir("io/juist/app/ui/theme").asFile
        dir.mkdirs()
        dir.resolve("Tokens.kt").writeText(out.toString().trimEnd() + "\n")
    }
}

val generateTokens = tasks.register<GenerateTokens>("generateTokens") {
    tokens.set(repo.file("design/tokens.json"))
    output.set(layout.buildDirectory.dir("generated/tokens"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.kotlin?.addGeneratedSourceDirectory(generateTokens, GenerateTokens::output)
    }
}

dependencies {
    implementation(files(repo.file("build/android/juist-core.aar")))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.service)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.core)
    implementation(libs.compose.ui.tooling.preview)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(libs.roborazzi.junit.rule)
    testImplementation(platform(libs.compose.bom))
    testImplementation(libs.compose.ui.test.junit4)
    testImplementation(libs.kotlinx.coroutines.test)
    debugImplementation(libs.compose.ui.test.manifest)
}
