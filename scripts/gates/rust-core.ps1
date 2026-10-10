$ErrorActionPreference = 'Stop'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo is required' }
& cargo test --workspace --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
