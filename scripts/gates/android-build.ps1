$ErrorActionPreference = 'Stop'
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw 'Java is required for Android build gate' }
if (-not (Test-Path env:ANDROID_HOME) -and -not (Test-Path env:ANDROID_SDK_ROOT)) { throw 'ANDROID_HOME or ANDROID_SDK_ROOT is required for Android build gate' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location -LiteralPath $repoRoot
try {
& cargo ndk -t arm64-v8a --platform 30 -o wear/app/src/main/jniLibs build -p openwearsync-android-ffi --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& .\gradlew.bat :wear:app:assembleDebug --no-daemon --no-watch-fs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally { Pop-Location }
