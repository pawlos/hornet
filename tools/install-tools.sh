#!/usr/bin/env bash
# Install .NET SDK, SharpFuzz.CommandLine global tool, and restore NuGet packages.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"

# Install .NET SDK if not present
if ! command -v dotnet &>/dev/null; then
    echo "=== Installing .NET 10 SDK ==="
    curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir "$DOTNET_ROOT"

    # Persist to ~/.bashrc if not already there
    if ! grep -q 'DOTNET_ROOT' ~/.bashrc 2>/dev/null; then
        echo '' >> ~/.bashrc
        echo '# .NET SDK' >> ~/.bashrc
        echo "export DOTNET_ROOT=\"$DOTNET_ROOT\"" >> ~/.bashrc
        echo 'export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"' >> ~/.bashrc
        echo "Added DOTNET_ROOT to ~/.bashrc"
    fi
    echo ""
fi

# SharpFuzz global tool targets net9.0 — install the runtime if missing
if ! dotnet --list-runtimes 2>/dev/null | grep -q 'Microsoft.NETCore.App 9\.'; then
    echo "=== Installing .NET 9 runtime (required by SharpFuzz) ==="
    curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 9.0 --runtime dotnet --install-dir "$DOTNET_ROOT"
    echo ""
fi

# Install AFL++ if not present
if ! command -v afl-fuzz &>/dev/null; then
    echo "=== Installing AFL++ ==="
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y afl++
    else
        echo "ERROR: apt not found. Install AFL++ manually: https://github.com/AFLplusplus/AFLplusplus"
        exit 1
    fi
    echo ""
fi

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
