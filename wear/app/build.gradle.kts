plugins { id("com.android.application"); kotlin("android") }
android { namespace = "com.openwearsync.wear"; compileSdk = 35
    defaultConfig { applicationId = "com.openwearsync.wear"; minSdk = 30; targetSdk = 35; versionCode = 1; versionName = "0.1.0" }
}
// START_MODULE_CONTRACT
// PURPOSE: Buildable Wear OS application shell.
// SCOPE: Packaging boundary only; behavior is implemented by later tasks.
// END_MODULE_CONTRACT
