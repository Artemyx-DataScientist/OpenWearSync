plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.compose")
}

android {
    namespace = "com.openwearsync.wear"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.openwearsync.wear"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.withType<Test>().configureEach {
    jvmArgs("-Djava.net.preferIPv4Stack=true")
    System.getenv("OPENWEARSYNC_NATIVE_TEST_DIR")?.let { jvmArgs("-Djava.library.path=$it") }
}

tasks.matching { it.name.contains("AarMetadata") }.configureEach {
    enabled = false
}

dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.wear.compose:compose-material3:1.6.2")
    implementation("androidx.wear.compose:compose-foundation:1.6.2")
    testImplementation(kotlin("test"))
}

// START_MODULE_CONTRACT
// PURPOSE: Buildable Wear OS application and JVM-testable Android platform adapters.
// SCOPE: Packaging and focused unit-test configuration only.
// LINKS: M-WEAR-SHELL, M-ANDROID-PLATFORM, V-M-ANDROID-PLATFORM
// END_MODULE_CONTRACT
