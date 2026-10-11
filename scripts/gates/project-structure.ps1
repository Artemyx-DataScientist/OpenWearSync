$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$required = @('Cargo.toml','Cargo.lock','rust-toolchain.toml','settings.gradle.kts','build.gradle.kts','gradle.properties','gradlew','gradlew.bat','wear/app/build.gradle.kts','desktop/app/build.gradle.kts','scripts/gates/rust-core.ps1','scripts/gates/android-unit.ps1','scripts/gates/android-build.ps1','scripts/gates/desktop-build.ps1','scripts/gates/protocol-contract.ps1','scripts/gates/receiver-integration.ps1','.github/workflows/build-and-test.yml')
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_)) })
if ($missing.Count) { throw "Missing required project paths: $($missing -join ', ')" }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo is required' }
& cargo metadata --format-version 1 --no-deps | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
Write-Output 'project-structure gate passed'
