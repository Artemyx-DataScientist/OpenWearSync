plugins { id("com.android.application"); kotlin("android") }

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
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.withType<Test>().configureEach {
    jvmArgs("-Djava.net.preferIPv4Stack=true", "-Dfile.encoding=UTF-8")
    classpath = testClassesDirs + files(layout.buildDirectory.dir("tmp/kotlin-classes/debug")) + classpath
}

dependencies {
    testImplementation(kotlin("test"))
}

// START_MODULE_CONTRACT
// PURPOSE: Buildable Wear OS application and JVM-testable Android platform adapters.
// SCOPE: Packaging and focused unit-test configuration only.
// LINKS: M-WEAR-SHELL, M-ANDROID-PLATFORM, V-M-ANDROID-PLATFORM
// END_MODULE_CONTRACT
