$ErrorActionPreference = 'Stop'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo is required' }
& cargo test -p openwearsync-receiver --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
