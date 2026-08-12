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

# --- pristine publish ---------------------------------------------------------
# Deliberately NOT instrumented: SharpFuzz's rewritten IL would be attributed as
# target coverage, and publish/<Harness> may be in use by a running campaign.
if [ "$REGEN" -eq 0 ]; then
    echo ""
    echo "=== Publishing (pristine) ==="
    dotnet publish "$ROOT_DIR/src/$HARNESS" -c Release -o "$PUBLISH_DIR" -v quiet --nologo
fi

APPHOST="$PUBLISH_DIR/$HARNESS"
if [ ! -x "$APPHOST" ]; then
    echo "ERROR: no app host at $APPHOST"
    exit 1
fi

# --- input selection ----------------------------------------------------------
INPUT_LIST="$(mktemp)"
trap 'rm -f "$INPUT_LIST" "${REPLAY_SH:-}"' EXIT

SEEDS=()
[ -d "$ROOT_DIR/$CORPUS_DIR" ] && while IFS= read -r f; do SEEDS+=("$f"); done \
    < <(find "$ROOT_DIR/$CORPUS_DIR" -maxdepth 1 -type f | sort)

QUEUE=()
QDIR="$ROOT_DIR/findings/$HARNESS/default/queue"
[ -d "$QDIR" ] && while IFS= read -r f; do QUEUE+=("$f"); done \
    < <(find "$QDIR" -maxdepth 1 -type f ! -name '.*' ! -name 'README*' | sort)

INPUT_TOTAL=$(( ${#SEEDS[@]} + ${#QUEUE[@]} ))
if [ "$INPUT_TOTAL" -eq 0 ]; then
    echo "ERROR: no inputs — neither $CORPUS_DIR nor a queue at findings/$HARNESS/default/queue"
    exit 1
fi

# Seeds are always replayed in full; only the queue is sampled.
: > "$INPUT_LIST"
[ ${#SEEDS[@]} -gt 0 ] && printf '%s\n' "${SEEDS[@]}" >> "$INPUT_LIST"

QUEUE_BUDGET=$(( MAX_INPUTS - ${#SEEDS[@]} ))
if [ ${#QUEUE[@]} -gt 0 ]; then
    if [ "$ALL_INPUTS" -eq 1 ] || [ "${#QUEUE[@]}" -le "$QUEUE_BUDGET" ]; then
        printf '%s\n' "${QUEUE[@]}" >> "$INPUT_LIST"
    else
        # Even stride across the queue, so the sample spans early and late discoveries.
        [ "$QUEUE_BUDGET" -lt 1 ] && QUEUE_BUDGET=1
        # awk reads a file rather than a pipe: its early exit() would SIGPIPE the
        # writing end, and pipefail would turn that into a fatal script error.
        QUEUE_FILE="$(mktemp)"
        printf '%s\n' "${QUEUE[@]}" > "$QUEUE_FILE"
        awk -v want="$QUEUE_BUDGET" -v have="${#QUEUE[@]}" \
            'BEGIN{step=have/want} NR>=int(n*step)+1 {print; n++} n>=want{exit}' \
            "$QUEUE_FILE" >> "$INPUT_LIST"
        rm -f "$QUEUE_FILE"
    fi
fi

sed -i '/^$/d' "$INPUT_LIST"
INPUT_USED=$(wc -l < "$INPUT_LIST")
echo "  inputs  : $INPUT_USED of $INPUT_TOTAL (${#SEEDS[@]} seed, ${#QUEUE[@]} queue)"
if [ "$INPUT_USED" -lt "$INPUT_TOTAL" ]; then
    echo "  NOTE: queue sampled — pass --all-inputs to replay everything"
fi
