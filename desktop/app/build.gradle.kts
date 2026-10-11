plugins {
    kotlin("jvm")
    id("org.jetbrains.compose")
    kotlin("plugin.compose")
}
kotlin { jvmToolchain(17) }

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
}

// START_MODULE_CONTRACT
// PURPOSE: Buildable Windows desktop application shell.
// SCOPE: Packaging boundary only; receiver behavior is implemented by later tasks.
// END_MODULE_CONTRACT

