$ErrorActionPreference = 'Stop'
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw 'Java is required for desktop build gate' }
& (Join-Path (Split-Path -Parent $PSScriptRoot) '..\gradlew.bat') :desktop:app:jar --no-daemon --no-watch-fs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
