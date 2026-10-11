$ErrorActionPreference = 'Stop'
if (-not $env:CARGO_TARGET_DIR -and (Test-Path 'D:\SignalWeaveCore-cargo-target')) { $env:CARGO_TARGET_DIR = 'D:\SignalWeaveCore-cargo-target' }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo is required' }
& cargo test -p openwearsync-receiver --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
