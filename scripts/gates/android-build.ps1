$ErrorActionPreference = 'Stop'
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw 'Java is required for Android build gate' }
if (-not (Test-Path env:ANDROID_HOME) -and -not (Test-Path env:ANDROID_SDK_ROOT)) { throw 'ANDROID_HOME or ANDROID_SDK_ROOT is required for Android build gate' }
& (Join-Path (Split-Path -Parent $PSScriptRoot) '..\gradlew.bat') :wear:app:assembleDebug --no-daemon
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
