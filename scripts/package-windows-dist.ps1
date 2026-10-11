# Packaging script for OpenWearSync Windows distribution artifacts (T-014, T-018)
$ErrorActionPreference = 'Stop'

$rootDir = Split-Path -Parent $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR -and (Test-Path 'D:\SignalWeaveCore-cargo-target')) {
    $env:CARGO_TARGET_DIR = 'D:\SignalWeaveCore-cargo-target'
}

Write-Host "Building OpenWearSync Windows Receiver Daemon..."
& cargo build --release --bin receiver_daemon --locked
if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with code $LASTEXITCODE" }

Write-Host "Building OpenWearSync Desktop UI application..."
& (Join-Path $rootDir 'gradlew.bat') :desktop:app:jar --no-daemon
if ($LASTEXITCODE -ne 0) { throw "Gradle desktop jar build failed with code $LASTEXITCODE" }

$distDir = Join-Path $rootDir 'dist\windows'
$binDir = Join-Path $distDir 'bin'
if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $rootDir 'target' }
$receiverExe = Join-Path $targetDir 'release\receiver_daemon.exe'
if (-not (Test-Path $receiverExe)) {
    throw "Receiver executable not found at $receiverExe"
}
Copy-Item $receiverExe (Join-Path $binDir 'openwearsync-receiver.exe')

$desktopJar = Join-Path $rootDir 'desktop\app\build\libs\app.jar'
if (-not (Test-Path $desktopJar)) {
    # Check for versioned jar
    $jars = Get-ChildItem (Join-Path $rootDir 'desktop\app\build\libs') -Filter '*.jar'
    if ($jars.Count -gt 0) {
        $desktopJar = $jars[0].FullName
    } else {
        throw "Desktop jar not found in desktop\app\build\libs"
    }
}
Copy-Item $desktopJar (Join-Path $binDir 'openwearsync-desktop.jar')

$launcherContent = @"
@echo off
title OpenWearSync Receiver Daemon
echo Starting OpenWearSync Receiver Daemon...
"%~dp0bin\openwearsync-receiver.exe"
pause
"@
Set-Content -Path (Join-Path $distDir 'start-receiver.cmd') -Value $launcherContent -Encoding ASCII

$readmeContent = @"
OpenWearSync Windows Distribution v0.1.0
=======================================

Components:
- bin\openwearsync-receiver.exe: Native Windows background receiver daemon (Rust)
- bin\openwearsync-desktop.jar: Compose Desktop GUI interface
- start-receiver.cmd: Quick launch batch script

Run start-receiver.cmd or bin\openwearsync-receiver.exe to start accepting audio
transfers over Wi-Fi from paired Wear OS devices.
"@
Set-Content -Path (Join-Path $distDir 'README.txt') -Value $readmeContent -Encoding UTF8

Write-Host "OpenWearSync Windows distribution successfully packaged to: $distDir"
Get-ChildItem -Recurse $distDir
