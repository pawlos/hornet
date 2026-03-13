#!/usr/bin/env bash
# Install SharpFuzz.CommandLine global tool and restore NuGet packages.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"

echo "=== Installing SharpFuzz.CommandLine global tool ==="
dotnet tool install --global SharpFuzz.CommandLine 2>/dev/null \
    || dotnet tool update --global SharpFuzz.CommandLine

echo ""
echo "=== Restoring NuGet packages ==="
dotnet restore "$ROOT_DIR/dotnet-fuzzing.sln"

echo ""
echo "=== Verifying tools ==="
echo -n "dotnet: "; dotnet --version
echo -n "sharpfuzz: "; sharpfuzz --version 2>&1 || echo "(installed)"
echo -n "afl-fuzz: "; afl-fuzz --version 2>&1 | head -1 || echo "NOT FOUND - install AFL++"

echo ""
echo "=== Done ==="
