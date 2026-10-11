$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location -LiteralPath $repoRoot
try {
    & cargo build -p openwearsync-receiver -p openwearsync-android-ffi --features openwearsync-receiver/integration-harness --locked
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $cargoMetadata = & cargo metadata --format-version 1 --no-deps --locked | ConvertFrom-Json
    $env:OPENWEARSYNC_NATIVE_TEST_DIR = Join-Path $cargoMetadata.target_directory 'debug'
    $env:OPENWEARSYNC_TEST_RECEIVER = Join-Path $env:OPENWEARSYNC_NATIVE_TEST_DIR 'receiver_test_harness.exe'
    & .\gradlew.bat :wear:app:testDebugUnitTest --rerun --tests 'com.openwearsync.wear.ClientReceiverIntegrationTest' --tests 'com.openwearsync.wear.PeerCredentialsStoreTest' --no-daemon --no-watch-fs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    [xml]$clientResult = Get-Content -LiteralPath 'wear/app/build/test-results/testDebugUnitTest/TEST-com.openwearsync.wear.ClientReceiverIntegrationTest.xml'
    if ([int]$clientResult.testsuite.tests -lt 5 -or [int]$clientResult.testsuite.skipped -ne 0) { throw 'Required Kotlin/JNI integration tests did not execute' }
} finally {
    Remove-Item Env:OPENWEARSYNC_TEST_RECEIVER,Env:OPENWEARSYNC_NATIVE_TEST_DIR -ErrorAction SilentlyContinue
    Pop-Location
}
