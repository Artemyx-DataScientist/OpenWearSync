plugins {
    id("com.android.application") version "8.5.2" apply false
    kotlin("android") version "2.0.21" apply false
    kotlin("jvm") version "2.0.21" apply false
    id("org.jetbrains.compose") version "1.7.0" apply false
}
group = "com.openwearsync"
version = "0.1.0"
tasks.register("buildWear") { dependsOn(":wear:app:assembleDebug") }
tasks.register("buildDesktop") { dependsOn(":desktop:app:jar") }
tasks.register("buildShippingArtifacts") { dependsOn("buildWear", "buildDesktop") }
