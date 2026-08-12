#!/usr/bin/env bash
# Generate a source-level coverage report for a harness by replaying its corpus
# under dotnet-coverage against a pristine (uninstrumented) publish.
# Usage: ./scripts/coverage-report.sh <Harness> [--all-inputs] [--max-inputs N] [--regen]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"

# R2R-precompiled methods run as native code the profiler never sees. Without this
# the report claims 0% for code that demonstrably executed.
export DOTNET_ReadyToRun=0

HARNESS="${1:-}"
if [ -z "$HARNESS" ] || [ "$HARNESS" = "--help" ]; then
    echo "Usage: ./scripts/coverage-report.sh <Harness> [--all-inputs] [--max-inputs N] [--regen]"
    exit 1
fi
shift

MAX_INPUTS=1500
ALL_INPUTS=0
REGEN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --all-inputs)  ALL_INPUTS=1; shift ;;
        --max-inputs)  MAX_INPUTS="$2"; shift 2 ;;
        --regen)       REGEN=1; shift ;;
        *) echo "ERROR: unknown option: $1"; exit 1 ;;
    esac
done

# --- config from HARNESSES.md -------------------------------------------------
ROW="$(grep -F "| $HARNESS | " "$ROOT_DIR/HARNESSES.md" | head -1 || true)"
if [ -z "$ROW" ]; then
    echo "ERROR: '$HARNESS' not found in HARNESSES.md. Known harnesses:"
    # Only real rows: the table header also starts with "| Harness |".
    grep -F 'instrument.sh' "$ROOT_DIR/HARNESSES.md" \
        | grep -oP '^\| \K[A-Za-z0-9._]+' | sort -u | sed 's/^/  /'
    exit 1
fi

field() { echo "$ROW" | awk -F'|' -v n="$1" '{gsub(/^ +| +$/,"",$n); gsub(/`/,"",$n); print $n}'; }
LIBRARY="$(field 3)"
VERSION="$(field 4)"
CORPUS_DIR="$(field 5)"
INSTRUMENT_CMD="$(field 6)"
TARGET_DLLS="$(echo "$INSTRUMENT_CMD" | sed "s|.*instrument\.sh  *$HARNESS  *||")"

PUBLISH_DIR="$ROOT_DIR/publish-cov/$HARNESS"
OUT_DIR="$ROOT_DIR/findings/$HARNESS/triage"
COBERTURA="$OUT_DIR/$HARNESS.cobertura.xml"

echo "=== $HARNESS ==="
echo "  library : $LIBRARY $VERSION"
echo "  corpus  : $CORPUS_DIR"
echo "  targets : $TARGET_DLLS"

# --- tool bootstrap -----------------------------------------------------------
# Both tools are diagnostic-only: they never touch the harness, the corpus, or
# the published binaries, so versions are deliberately unpinned.
ensure_tool() {
    local cmd="$1" pkg="$2"
    command -v "$cmd" &>/dev/null && return 0
    echo "  installing $pkg (not found)"
    if ! dotnet tool install --global "$pkg" >/dev/null 2>&1; then
        echo "ERROR: could not install $pkg. Install it manually:"
        echo "  dotnet tool install --global $pkg"
        exit 1
    fi
}
ensure_tool dotnet-coverage dotnet-coverage
ensure_tool dotnet-symbol   dotnet-symbol
