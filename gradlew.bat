@echo off
where gradle >NUL 2>&1
if errorlevel 1 (
  echo Gradle is required; install Gradle 8.10.2 or use the configured environment. 1>&2
  exit /b 1
)
gradle %*
