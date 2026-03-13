#!/usr/bin/env bash
# Hornet batch runner — fuzz all (or selected) harnesses sequentially.
# Each harness gets multi-core fuzzing for a configurable duration,
# followed by automatic triage.
#
# Usage:
#   ./scripts/fuzz-batch.sh [options] [harness1 harness2 ...]
#
# Options:
#   --duration DURATION   Time per harness (default: 2h). Supports s/m/h suffixes.
#   --cores N             AFL++ instances per harness (default: half of available)
#   --skip-triage         Don't auto-triage after each harness
#   --dry-run             Show what would run without actually fuzzing
#
# Examples:
#   ./scripts/fuzz-batch.sh                                    # All harnesses, 2h each
#   ./scripts/fuzz-batch.sh --duration 30m Harness.ImageSharp  # One harness, 30 min
#   ./scripts/fuzz-batch.sh --duration 1h --cores 4            # All, 1h each, 4 cores
#   ./scripts/fuzz-batch.sh --dry-run                          # Preview the plan
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

# Defaults
DURATION="2h"
CORES=0
SKIP_TRIAGE=false
DRY_RUN=false
HARNESSES=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration|-d)  DURATION="$2"; shift 2 ;;
        --cores|-c)     CORES="$2"; shift 2 ;;
        --skip-triage)  SKIP_TRIAGE=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --help|-h)
            sed -n '2,/^set /{ /^#/s/^# \?//p }' "$0"
            exit 0
            ;;
        *)              HARNESSES+=("$1"); shift ;;
    esac
done

# Parse duration to seconds
parse_duration() {
    local val="$1"
    local num="${val%[smhSMH]}"
    local suffix="${val##*[0-9]}"
    case "${suffix,,}" in
        s) echo "$num" ;;
        m) echo $((num * 60)) ;;
        h) echo $((num * 3600)) ;;
        *) echo "$num" ;;  # bare number = seconds
    esac
}

DURATION_SECS=$(parse_duration "$DURATION")

# Auto-detect cores
if [ "$CORES" -eq 0 ]; then
    AVAILABLE=$(nproc)
    CORES=$(( AVAILABLE / 2 ))
    [ "$CORES" -lt 2 ] && CORES=2
fi

# Auto-discover corpus for a harness by convention:
#   Harness.Foo -> corpora/foo (lowercase name after "Harness.")
# Falls back to explicit overrides for non-standard names.
declare -A CORPUS_OVERRIDES=(
    [DemoHarness]="demo"
    # Add overrides here when the corpus dir name doesn't match the convention.
    # Convention: Harness.FooBar -> corpora/foobar (lowercase, strip "Harness." prefix)
    # Example: [Harness.CsvHelper]="csv"
)

find_corpus() {
    local harness="$1"
    # Check explicit override first
    if [ -n "${CORPUS_OVERRIDES[$harness]:-}" ]; then
        echo "${CORPUS_OVERRIDES[$harness]}"
        return
    fi
    # Convention: Harness.FooBar -> foobar
    local alias
    alias="$(echo "$harness" | sed 's/^Harness\.//' | tr '[:upper:]' '[:lower:]')"
    echo "$alias"
}

# If no harnesses specified, auto-discover from publish/ directory
if [ ${#HARNESSES[@]} -eq 0 ]; then
    for dll in "$ROOT_DIR"/publish/Harness.*/Harness.*.dll; do
        [ -f "$dll" ] || continue
        harness=$(basename "$(dirname "$dll")")
        corpus=$(find_corpus "$harness")
        corpus_dir="$ROOT_DIR/corpora/$corpus"
        if [ -d "$corpus_dir" ]; then
            HARNESSES+=("$harness")
        else
            echo "SKIP: $harness (no corpus at corpora/$corpus)"
        fi
    done
    # Sort for consistent ordering
    IFS=$'\n' HARNESSES=($(sort <<<"${HARNESSES[*]}")); unset IFS
fi

# Validate all harnesses before starting
for harness in "${HARNESSES[@]}"; do
    corpus=$(find_corpus "$harness")
    if [ ! -f "$ROOT_DIR/publish/$harness/$harness.dll" ]; then
        echo "ERROR: $harness not published. Run instrument.sh first."
        exit 1
    fi
    if [ ! -d "$ROOT_DIR/corpora/$corpus" ]; then
        echo "ERROR: Corpus not found: corpora/$corpus"
        exit 1
    fi
done

TOTAL=${#HARNESSES[@]}
TOTAL_TIME=$((DURATION_SECS * TOTAL))

format_time() {
    local secs=$1
    if [ "$secs" -ge 3600 ]; then
        printf "%dh%02dm" $((secs / 3600)) $(((secs % 3600) / 60))
    elif [ "$secs" -ge 60 ]; then
        printf "%dm%02ds" $((secs / 60)) $((secs % 60))
    else
        printf "%ds" "$secs"
    fi
}

# Print plan
echo "=== Hornet Batch Runner ==="
echo "Harnesses:  $TOTAL"
echo "Duration:   $DURATION each ($(format_time $TOTAL_TIME) total)"
echo "Cores:      $CORES per harness"
echo "Triage:     $([ "$SKIP_TRIAGE" = true ] && echo "disabled" || echo "after each run")"
echo ""
echo "Schedule:"
for i in "${!HARNESSES[@]}"; do
    harness="${HARNESSES[$i]}"
    corpus=$(find_corpus "$harness")
    printf "  %2d. %-30s  corpus: %-20s\n" $((i + 1)) "$harness" "$corpus"
done
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "(dry run — exiting)"
    exit 0
fi

# Results tracking
REPORT_FILE="$ROOT_DIR/findings/.batch-report-$(date '+%Y%m%d-%H%M%S').txt"
echo "Hornet Batch Report — $(date)" > "$REPORT_FILE"
echo "Duration per harness: $DURATION ($DURATION_SECS seconds)" >> "$REPORT_FILE"
echo "Cores: $CORES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

BATCH_START=$(date +%s)

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_SKIP_BIN_CHECK=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_TMPDIR="${AFL_TMPDIR:-/tmp}"
export AFL_NO_UI=1
export DOTNET_TieredCompilation=0
export DOTNET_ReadyToRun=0

run_harness() {
    local harness="$1"
    local corpus_dir="$ROOT_DIR/corpora/$(find_corpus "$harness")"
    local findings_dir="$ROOT_DIR/findings/$harness"
    local harness_dll="$ROOT_DIR/publish/$harness/$harness.dll"
    local harness_exe="$ROOT_DIR/publish/$harness/$harness"
    local log_dir="$findings_dir/.logs"

    mkdir -p "$findings_dir" "$log_dir"

    # Detect self-contained vs framework-dependent
    local target_cmd
    if [ -f "$ROOT_DIR/publish/$harness/libcoreclr.so" ]; then
        target_cmd=("$harness_exe" "$harness_dll")
    else
        target_cmd=("$DOTNET" "$harness_dll")
    fi

    # Auto-detect dictionary
    local dict_args=()
    local dict_alias
    dict_alias="$(echo "$harness" | sed 's/^Harness\.//' | tr '[:upper:]' '[:lower:]')"
    if [ -f "$ROOT_DIR/dictionaries/$dict_alias.dict" ]; then
        dict_args=(-x "$ROOT_DIR/dictionaries/$dict_alias.dict")
    fi

    local pids=()

    # Launch main
    afl-fuzz -i "$corpus_dir" -o "$findings_dir" -t 5000 -M main \
        "${dict_args[@]}" -- "${target_cmd[@]}" \
        > "$log_dir/main.log" 2>&1 &
    pids+=($!)

    sleep 2

    # Launch secondaries
    for i in $(seq 1 $((CORES - 1))); do
        afl-fuzz -i "$corpus_dir" -o "$findings_dir" -t 5000 -S "secondary$i" \
            "${dict_args[@]}" -- "${target_cmd[@]}" \
            > "$log_dir/secondary$i.log" 2>&1 &
        pids+=($!)
        sleep 1
    done

    # Wait for duration
    sleep "$DURATION_SECS"

    # Stop all instances
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true

    # Count results
    local crashes=0 paths=0
    for dir in "$findings_dir"/*/; do
        [ -d "$dir" ] || continue
        local instance
        instance=$(basename "$dir")
        [[ "$instance" == .* ]] && continue
        local c
        c=$(find "$dir/crashes" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        local q
        q=$(find "$dir/queue" -maxdepth 1 -type f 2>/dev/null | wc -l)
        crashes=$((crashes + c))
        paths=$((paths + q))
    done

    echo "$crashes|$paths"
}

# Main loop
for i in "${!HARNESSES[@]}"; do
    harness="${HARNESSES[$i]}"
    step=$((i + 1))

    echo "=== [$step/$TOTAL] $harness ($DURATION, $CORES cores) ==="
    start_time=$(date +%s)

    result=$(run_harness "$harness")
    crashes=$(echo "$result" | cut -d'|' -f1)
    paths=$(echo "$result" | cut -d'|' -f2)

    elapsed=$(( $(date +%s) - start_time ))
    echo "  Done in $(format_time $elapsed): $paths paths, $crashes crashes"

    # Auto-triage if crashes found
    if [ "$SKIP_TRIAGE" = false ] && [ "$crashes" -gt 0 ]; then
        echo "  Triaging..."
        if "$SCRIPT_DIR/triage.sh" "$harness" > /dev/null 2>&1; then
            unique=$(find "$ROOT_DIR/findings/$harness/triage" -name "*.info" 2>/dev/null | wc -l)
            echo "  Triage: $unique unique bugs"
            crashes_info="$crashes crashes ($unique unique)"
        else
            echo "  Triage failed"
            crashes_info="$crashes crashes"
        fi
    else
        crashes_info="$crashes crashes"
    fi

    # Log to report
    printf "%-30s  %s paths, %s  (%s)\n" "$harness" "$paths" "$crashes_info" "$(format_time $elapsed)" >> "$REPORT_FILE"
    echo ""
done

BATCH_ELAPSED=$(( $(date +%s) - BATCH_START ))

# Final summary
echo "=== Batch Complete ==="
echo "Total time: $(format_time $BATCH_ELAPSED)"
echo "Report: $REPORT_FILE"
echo ""

echo "" >> "$REPORT_FILE"
echo "Total time: $(format_time $BATCH_ELAPSED)" >> "$REPORT_FILE"

# Print summary table
echo "Results:"
cat "$REPORT_FILE"
