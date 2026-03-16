#!/usr/bin/env bash
# Run AFL++ against a published+instrumented harness.
# Usage: ./scripts/fuzz-afl.sh <harness-name> <corpus-dir> [extra-afl-args...]
# Example: ./scripts/fuzz-afl.sh DemoHarness corpora/demo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

# Parse optional flags
while getopts "" opt; do
    case $opt in
        *) echo "Usage: fuzz-afl.sh <harness-name> <corpus-dir> [extra-afl-args...]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

HARNESS_NAME="${1:?Usage: fuzz-afl.sh <harness-name> <corpus-dir> [extra-afl-args...]}"
CORPUS_DIR="${2:?Usage: fuzz-afl.sh <harness-name> <corpus-dir> [extra-afl-args...]}"
shift 2
EXTRA_ARGS=("$@")

HARNESS_DLL="$ROOT_DIR/publish/$HARNESS_NAME/$HARNESS_NAME.dll"
HARNESS_EXE="$ROOT_DIR/publish/$HARNESS_NAME/$HARNESS_NAME"
FINDINGS_DIR="$ROOT_DIR/findings/$HARNESS_NAME"

# Resolve corpus dir relative to ROOT_DIR if not absolute
if [[ "$CORPUS_DIR" != /* ]]; then
    CORPUS_DIR="$ROOT_DIR/$CORPUS_DIR"
fi

if [ ! -f "$HARNESS_DLL" ]; then
    echo "ERROR: Harness DLL not found: $HARNESS_DLL"
    echo "Run: ./scripts/instrument.sh $HARNESS_NAME <dlls...>"
    exit 1
fi

if [ ! -d "$CORPUS_DIR" ]; then
    echo "ERROR: Corpus directory not found: $CORPUS_DIR"
    exit 1
fi

# Create findings directory
mkdir -p "$FINDINGS_DIR"

# Auto-resume: if findings already exist, use "-i -" to continue from where we left off.
# New corpus seeds can be added by placing them in the queue directory before resuming.
INPUT_ARG="$CORPUS_DIR"
if [ -d "$FINDINGS_DIR/default/queue" ] && [ "$(ls -A "$FINDINGS_DIR/default/queue" 2>/dev/null)" ]; then
    INPUT_ARG="-"
    echo "Resuming from existing findings (use 'rm -rf $FINDINGS_DIR' to start fresh)"
fi

# Set AFL++ performance settings
export AFL_SKIP_CPUFREQ=1
export AFL_SKIP_BIN_CHECK=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_TMPDIR="${AFL_TMPDIR:-/tmp}"  # WSL2: /mnt/c doesn't support ftruncate
export AFL_NO_UI="${AFL_NO_UI:-0}"

# Reduce .NET JIT non-determinism that causes AFL++ instability warnings
export DOTNET_TieredCompilation=0
export DOTNET_ReadyToRun=0

# Detect self-contained vs framework-dependent publish.
# Self-contained bundles the runtime (libcoreclr.so) alongside the app.
if [ -f "$ROOT_DIR/publish/$HARNESS_NAME/libcoreclr.so" ]; then
    TARGET_CMD=("$HARNESS_EXE" "$HARNESS_DLL")
    echo "=== Starting AFL++ (self-contained) ==="
else
    TARGET_CMD=("$DOTNET" "$HARNESS_DLL")
    echo "=== Starting AFL++ (framework-dependent) ==="
fi

# Auto-detect dictionary: look for dictionaries/<harness-name>.dict or common aliases
DICT_ARGS=()
DICT_DIR="$ROOT_DIR/dictionaries"
# Try exact harness name match first (e.g., Harness.MimeKit -> mimekit.dict via lowercase after dot)
DICT_ALIAS="$(echo "$HARNESS_NAME" | sed 's/^Harness\.//' | tr '[:upper:]' '[:lower:]')"
if [ -f "$DICT_DIR/$DICT_ALIAS.dict" ]; then
    DICT_ARGS=(-x "$DICT_DIR/$DICT_ALIAS.dict")
    echo "Dictionary: $DICT_DIR/$DICT_ALIAS.dict"
elif [ -f "$DICT_DIR/$HARNESS_NAME.dict" ]; then
    DICT_ARGS=(-x "$DICT_DIR/$HARNESS_NAME.dict")
    echo "Dictionary: $DICT_DIR/$HARNESS_NAME.dict"
else
    echo "Dictionary: (none found)"
fi

echo "Harness: ${TARGET_CMD[*]}"
echo "Corpus:  $CORPUS_DIR"
echo "Findings: $FINDINGS_DIR"
echo ""

exec afl-fuzz \
    -i "$INPUT_ARG" \
    -o "$FINDINGS_DIR" \
    -t 5000 \
    -m none \
    "${DICT_ARGS[@]}" \
    "${EXTRA_ARGS[@]}" \
    -- "${TARGET_CMD[@]}"
