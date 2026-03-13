#!/usr/bin/env bash
# Run multiple AFL++ instances in parallel (1 main + N-1 secondary).
# Usage: ./scripts/fuzz-multi.sh <harness-name> <corpus-dir> [--cores N]
# Example: ./scripts/fuzz-multi.sh Harness.ImageSharp corpora/imagesharp --cores 4
# Press Ctrl+C to stop all instances.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

# Parse arguments
HARNESS_NAME=""
CORPUS_DIR=""
CORES=0  # 0 = auto-detect (half of available)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cores|-c)
            CORES="$2"
            shift 2
            ;;
        *)
            if [ -z "$HARNESS_NAME" ]; then
                HARNESS_NAME="$1"
            elif [ -z "$CORPUS_DIR" ]; then
                CORPUS_DIR="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$HARNESS_NAME" ] || [ -z "$CORPUS_DIR" ]; then
    echo "Usage: fuzz-multi.sh <harness-name> <corpus-dir> [--cores N]"
    echo ""
    echo "Options:"
    echo "  --cores N    Number of AFL++ instances (default: half of $(nproc) cores)"
    echo ""
    echo "Examples:"
    echo "  ./scripts/fuzz-multi.sh Harness.ImageSharp corpora/imagesharp"
    echo "  ./scripts/fuzz-multi.sh Harness.ImageSharp corpora/imagesharp --cores 8"
    exit 1
fi

# Auto-detect core count: use half of available (leave room for OS + .NET runtime)
if [ "$CORES" -eq 0 ]; then
    AVAILABLE=$(nproc)
    CORES=$(( AVAILABLE / 2 ))
    [ "$CORES" -lt 2 ] && CORES=2
fi

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

mkdir -p "$FINDINGS_DIR"

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_SKIP_BIN_CHECK=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_TMPDIR="${AFL_TMPDIR:-/tmp}"
export AFL_NO_UI=1  # Must use no-UI for parallel (only one can own the terminal)
export DOTNET_TieredCompilation=0
export DOTNET_ReadyToRun=0

# Detect self-contained vs framework-dependent
if [ -f "$ROOT_DIR/publish/$HARNESS_NAME/libcoreclr.so" ]; then
    TARGET_CMD=("$HARNESS_EXE" "$HARNESS_DLL")
    MODE="self-contained"
else
    TARGET_CMD=("$DOTNET" "$HARNESS_DLL")
    MODE="framework-dependent"
fi

# Auto-detect dictionary
DICT_ARGS=()
DICT_DIR="$ROOT_DIR/dictionaries"
DICT_ALIAS="$(echo "$HARNESS_NAME" | sed 's/^Harness\.//' | tr '[:upper:]' '[:lower:]')"
if [ -f "$DICT_DIR/$DICT_ALIAS.dict" ]; then
    DICT_ARGS=(-x "$DICT_DIR/$DICT_ALIAS.dict")
    DICT_NAME="$DICT_ALIAS.dict"
elif [ -f "$DICT_DIR/$HARNESS_NAME.dict" ]; then
    DICT_ARGS=(-x "$DICT_DIR/$HARNESS_NAME.dict")
    DICT_NAME="$HARNESS_NAME.dict"
else
    DICT_NAME="(none)"
fi

echo "=== Hornet Multi-Core Fuzzing ==="
echo "Harness:    $HARNESS_NAME ($MODE)"
echo "Corpus:     $CORPUS_DIR"
echo "Findings:   $FINDINGS_DIR"
echo "Dictionary: $DICT_NAME"
echo "Instances:  $CORES (1 main + $((CORES - 1)) secondary)"
echo ""

# Track child PIDs for cleanup
PIDS=()
LOG_DIR="$FINDINGS_DIR/.logs"
mkdir -p "$LOG_DIR"

cleanup() {
    echo ""
    echo "=== Stopping all instances ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true

    # Print final stats
    echo ""
    echo "=== Final Stats ==="
    for dir in "$FINDINGS_DIR"/*/; do
        [ -d "$dir" ] || continue
        instance=$(basename "$dir")
        [[ "$instance" == .* ]] && continue
        crashes=$(find "$dir/crashes" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        hangs=$(find "$dir/hangs" -maxdepth 1 -type f 2>/dev/null | wc -l)
        queue=$(find "$dir/queue" -maxdepth 1 -type f 2>/dev/null | wc -l)
        echo "  $instance: $queue paths, $crashes crashes, $hangs hangs"
    done

    # Aggregate unique crashes across all instances
    total_crashes=0
    for dir in "$FINDINGS_DIR"/*/crashes/; do
        [ -d "$dir" ] || continue
        count=$(find "$dir" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        total_crashes=$((total_crashes + count))
    done
    echo ""
    echo "  Total crashes (may include duplicates): $total_crashes"
    echo ""
    echo "Run ./scripts/triage.sh $HARNESS_NAME to deduplicate and classify."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Launch main instance
echo "Starting main instance..."
afl-fuzz \
    -i "$CORPUS_DIR" \
    -o "$FINDINGS_DIR" \
    -t 5000 \
    -M main \
    "${DICT_ARGS[@]}" \
    -- "${TARGET_CMD[@]}" \
    > "$LOG_DIR/main.log" 2>&1 &
PIDS+=($!)
echo "  main (PID $!) -> $LOG_DIR/main.log"

# Wait a moment for main to initialize the sync dir
sleep 2

# Launch secondary instances
for i in $(seq 1 $((CORES - 1))); do
    echo "Starting secondary$i..."
    afl-fuzz \
        -i "$CORPUS_DIR" \
        -o "$FINDINGS_DIR" \
        -t 5000 \
        -S "secondary$i" \
        "${DICT_ARGS[@]}" \
        -- "${TARGET_CMD[@]}" \
        > "$LOG_DIR/secondary$i.log" 2>&1 &
    PIDS+=($!)
    echo "  secondary$i (PID $!) -> $LOG_DIR/secondary$i.log"
    sleep 1
done

echo ""
echo "=== All $CORES instances running ==="
echo "Press Ctrl+C to stop."
echo ""
echo "Monitor progress:"
echo "  watch -n5 'afl-whatsup $FINDINGS_DIR'"
echo "  tail -f $LOG_DIR/main.log"
echo ""

# Wait and periodically show status
while true; do
    sleep 60

    # Check if any instance died
    alive=0
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive=$((alive + 1))
        fi
    done

    if [ "$alive" -eq 0 ]; then
        echo "All instances have stopped."
        cleanup
        break
    fi

    # Show brief status
    crashes=0
    for dir in "$FINDINGS_DIR"/*/crashes/; do
        [ -d "$dir" ] || continue
        count=$(find "$dir" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        crashes=$((crashes + count))
    done
    echo "[$(date '+%H:%M:%S')] $alive/$CORES instances alive, $crashes total crashes"
done
