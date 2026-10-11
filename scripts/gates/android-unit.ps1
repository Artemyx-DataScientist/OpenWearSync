$ErrorActionPreference = 'Stop'
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw 'Java is required for Android unit test gate' }
if (-not (Test-Path env:ANDROID_HOME) -and -not (Test-Path env:ANDROID_SDK_ROOT)) { throw 'ANDROID_HOME or ANDROID_SDK_ROOT is required for Android unit test gate' }
& (Join-Path (Split-Path -Parent $PSScriptRoot) '..\gradlew.bat') :wear:app:testDebugUnitTest --rerun --no-daemon --no-watch-fs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
