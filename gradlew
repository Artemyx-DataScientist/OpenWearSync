#!/usr/bin/env sh
set -eu
if ! command -v gradle >/dev/null 2>&1; then echo "Gradle is required; install Gradle 8.10.2 or use the configured environment." >&2; exit 1; fi
exec gradle "$@"
