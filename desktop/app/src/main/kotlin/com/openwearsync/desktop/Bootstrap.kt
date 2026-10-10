package com.openwearsync.desktop

// START_MODULE_CONTRACT
// PURPOSE: Reserve the desktop application entry boundary.
// SCOPE: Windows desktop Compose UI application shell and status viewer.
// DEPENDS: M-WINDOWS-RECEIVER, M-TRANSFER-REGISTRY
// LINKS: M-DESKTOP-UI, M-WINDOWS-RECEIVER, V-M-DESKTOP-UI
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   DesktopApp - Compose Desktop application entry and receiver controller.
// END_MODULE_MAP

class DesktopApp {
    fun appVersion(): String = "0.1.0"
}
