package com.openwearsync.wear

// START_MODULE_CONTRACT
// PURPOSE: Reserve the Wear application entry boundary.
// SCOPE: Wear OS application shell and lifecycle entry.
// DEPENDS: M-ANDROID-PLATFORM, M-TRANSFER-CORE
// LINKS: M-WEAR-SHELL, M-ANDROID-PLATFORM, V-M-WEAR-SHELL
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   WearApp - main Wear OS application entry and state container.
// END_MODULE_MAP

class WearApp {
    fun appVersion(): String = "0.1.0"
}
