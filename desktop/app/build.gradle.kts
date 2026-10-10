plugins {
    kotlin("jvm")
    id("org.jetbrains.compose")
    kotlin("plugin.compose")
}
kotlin { jvmToolchain(17) }
// START_MODULE_CONTRACT
// PURPOSE: Buildable Windows desktop application shell.
// SCOPE: Packaging boundary only; receiver behavior is implemented by later tasks.
// END_MODULE_CONTRACT
