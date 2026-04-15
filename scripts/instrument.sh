#!/usr/bin/env bash
# Publish a harness and instrument target DLLs with SharpFuzz.
# For BCL (runtime) DLLs, copies them from the shared framework and strips R2R first.
# Usage: ./scripts/instrument.sh <harness-name> [dll1 dll2 ...]
# Example: ./scripts/instrument.sh DemoHarness Newtonsoft.Json.dll
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"
export DOTNET_ROLL_FORWARD=Major

HARNESS_NAME="${1:?Usage: instrument.sh <harness-name> [dll1 dll2 ...]}"
shift
DLLS_TO_INSTRUMENT=("$@")

HARNESS_DIR="$ROOT_DIR/src/$HARNESS_NAME"
PUBLISH_DIR="$ROOT_DIR/publish/$HARNESS_NAME"
STRIP_R2R_DIR="$ROOT_DIR/tools/StripR2R"

if [ ! -d "$HARNESS_DIR" ]; then
    echo "ERROR: Harness directory not found: $HARNESS_DIR"
    exit 1
fi

# ildasm/ilasm paths (installed via NuGet)
ILDASM="$HOME/.nuget/packages/runtime.linux-x64.microsoft.netcore.ildasm/10.0.3/runtimes/linux-x64/native/ildasm"
ILASM="$HOME/.nuget/packages/runtime.linux-x64.microsoft.netcore.ilasm/10.0.3/runtimes/linux-x64/native/ilasm"

# Fallback R2R stripper for mixed-mode assemblies that Mono.Cecil can't handle.
# Uses ildasm → fix IL → ilasm roundtrip to produce a pure MSIL DLL.
strip_via_ilasm() {
    local dll_path="$1"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local il_file="$tmp_dir/assembly.il"

    if [ ! -x "$ILDASM" ] || [ ! -x "$ILASM" ]; then
        echo "ERROR: ildasm/ilasm not found. Run:"
        echo "  dotnet restore a project referencing runtime.linux-x64.Microsoft.NETCore.ILDAsm/ILAsm 10.0.3"
        rm -rf "$tmp_dir"
        return 1
    fi

    # Disassemble
    "$ILDASM" -out="$il_file" "$dll_path"

    # Fix known ilasm issues: bad hex format strings and mixed-mode corflags
    sed -i 's/0x%016I64x/0x0000000000100000/g' "$il_file"
    sed -i 's/\.corflags 0x0000000[cC]/\.corflags 0x00000001/' "$il_file"

    # Reassemble as pure IL
    "$ILASM" -dll -output="$dll_path" "$il_file"

    rm -rf "$tmp_dir"
    echo "Stripped R2R (via ilasm): $(basename "$dll_path")"
}

# Build the StripR2R tool if needed
echo "=== Building StripR2R tool ==="
dotnet build "$STRIP_R2R_DIR" -c Release -v quiet

echo ""
echo "=== Publishing $HARNESS_NAME (framework-dependent) ==="
# Remove target DLLs before publishing so dotnet publish always writes a fresh copy
for dll in "${DLLS_TO_INSTRUMENT[@]}"; do
    rm -f "$PUBLISH_DIR/$dll"
done
dotnet publish "$HARNESS_DIR" \
    -c Release \
    -o "$PUBLISH_DIR" \
    /p:UseAppHost=true

# Find the .NET shared framework directory for copying BCL DLLs
FRAMEWORK_DIR="$(find "$DOTNET_ROOT/shared/Microsoft.NETCore.App" -maxdepth 1 -type d -name '10.*' | sort -V | tail -1)"
# Fallback to any version if .NET 10 not found
if [ -z "$FRAMEWORK_DIR" ]; then
    FRAMEWORK_DIR="$(find "$DOTNET_ROOT/shared/Microsoft.NETCore.App" -maxdepth 1 -type d | sort -V | tail -1)"
fi

echo ""
echo "=== Instrumenting DLLs ==="
for dll in "${DLLS_TO_INSTRUMENT[@]}"; do
    dll_path="$PUBLISH_DIR/$dll"

    # If the DLL exists in the shared framework, always copy fresh to avoid re-instrumenting a stale copy
    if [ -n "$FRAMEWORK_DIR" ] && [ -f "$FRAMEWORK_DIR/$dll" ]; then
        echo "Copying BCL DLL from framework: $dll"
        cp "$FRAMEWORK_DIR/$dll" "$dll_path"
    fi

    if [ -f "$dll_path" ]; then
        # Strip R2R native code (Mono.Cecil re-write produces pure IL)
        echo "Stripping R2R: $dll"
        if ! dotnet run --project "$STRIP_R2R_DIR" -c Release -- "$dll_path" 2>&1; then
            echo "Mono.Cecil failed (mixed-mode?), trying ildasm/ilasm roundtrip..."
            strip_via_ilasm "$dll_path"
        fi

        echo "Instrumenting: $dll"
        sharpfuzz "$dll_path"
    else
        echo "WARNING: DLL not found, skipping: $dll_path"
    fi
done

echo ""
echo "=== Done ==="
echo "Published to: $PUBLISH_DIR"
