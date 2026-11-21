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
#   --cores N             AFL++ instances per harness (default: quarter of available, min 2)
#   --memory-limit MB     Virtual address-space cap per AFL++ instance in MB (default: 8192).
#                         This is AFL's -m (RLIMIT_AS), not committed RAM. .NET reserves
#                         multi-GB of address space at startup, so values <4096 make every
#                         .NET harness crash the dry-run. Bound runaway allocations on
#                         memory-constrained systems like WSL2 without starving .NET.
#   --skip-triage         Don't auto-triage (crashes or hangs) after each harness
#   --skip-hang-triage    Triage crashes but skip hang triage (which replays each
#                         deduplicated hang standalone for up to CONFIRM_TIMEOUT and
#                         can dominate wall-clock when a harness has many hangs)
#   --dry-run             Show what would run without actually fuzzing
#
# Examples:
#   ./scripts/fuzz-batch.sh                                    # All harnesses, 2h each
#   ./scripts/fuzz-batch.sh --duration 30m Harness.ImageSharp  # One harness, 30 min
#   ./scripts/fuzz-batch.sh --duration 1h --cores 4            # All, 1h each, 4 cores
#   ./scripts/fuzz-batch.sh --memory-limit 1024                # 1GB per instance
#   ./scripts/fuzz-batch.sh --dry-run                          # Preview the plan
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"
# shellcheck source=lib/afl-target.sh
source "$SCRIPT_DIR/lib/afl-target.sh"

# Defaults
DURATION="2h"
CORES=0
MEMORY_LIMIT=8192  # MB per AFL++ instance. NOTE: AFL's -m caps virtual ADDRESS SPACE
                   # (RLIMIT_AS), not committed RAM. .NET reserves multi-GB of address
                   # space at startup (but commits little), so values <4096 make every
                   # .NET harness crash AFL's dry-run. 8192 clears that with headroom for
                   # heavier harnesses; raising it is cheap (uncommitted AS != real RAM).
SKIP_TRIAGE=false
SKIP_HANG_TRIAGE=false
DRY_RUN=false
HARNESSES=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration|-d)       DURATION="$2"; shift 2 ;;
        --cores|-c)          CORES="$2"; shift 2 ;;
        --memory-limit|-m)   MEMORY_LIMIT="$2"; shift 2 ;;
        --skip-triage)       SKIP_TRIAGE=true; shift ;;
        --skip-hang-triage)  SKIP_HANG_TRIAGE=true; shift ;;
        --dry-run)           DRY_RUN=true; shift ;;
        --help|-h)
            sed -n '2,/^set /{ /^#/s/^# \?//p }' "$0"
            exit 0
            ;;
        *)                   HARNESSES+=("$1"); shift ;;
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

# Auto-detect cores — use quarter of available (not half) to reduce memory pressure
if [ "$CORES" -eq 0 ]; then
    AVAILABLE=$(nproc)
    CORES=$(( AVAILABLE / 4 ))
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
echo "Memory:     ${MEMORY_LIMIT}MB per AFL++ instance ($(( MEMORY_LIMIT * CORES ))MB max total)"
if [ "$SKIP_TRIAGE" = true ]; then
    echo "Triage:     disabled"
elif [ "$SKIP_HANG_TRIAGE" = true ]; then
    echo "Triage:     crashes only (hang triage skipped)"
else
    echo "Triage:     crashes + hangs after each run"
fi
echo ""
echo "Schedule:"
for i in "${!HARNESSES[@]}"; do
    harness="${HARNESSES[$i]}"
    corpus=$(find_corpus "$harness")
    printf "  %2d. %-30s  corpus: %-20s\n" $((i + 1)) "$harness" "$corpus"
done
echo ""

# Pre-flight: flag broken self-contained publishes before spending any time.
# A self-contained harness whose runtimeconfig.json still declares a shared
# "framework" dependency while a leftover libcoreclr.so sits in the publish dir
# is a broken hybrid (re-instrumented framework-dependent on top of an older
# self-contained publish) and will do 0 execs. Catch it up front so it's visible
# in the first second instead of after a wasted 30m slot.
PREFLIGHT_BAD=()
for harness in "${HARNESSES[@]}"; do
    pdir="$ROOT_DIR/publish/$harness"
    if [ -f "$pdir/libcoreclr.so" ] && grep -q '"framework"' "$pdir/$harness.runtimeconfig.json" 2>/dev/null; then
        PREFLIGHT_BAD+=("$harness")
    fi
done
if [ ${#PREFLIGHT_BAD[@]} -gt 0 ]; then
    echo "⚠ PRE-FLIGHT WARNING: broken hybrid publish dir (will do 0 execs):"
    for h in "${PREFLIGHT_BAD[@]}"; do echo "    - $h"; done
    echo "  Fix: ensure the csproj sets <SelfContained>true</SelfContained>, then re-run instrument.sh."
    echo "  (They will also be auto-skipped ~20s into their slot by the health check.)"
    echo ""
fi

if [ "$DRY_RUN" = true ]; then
    echo "(dry run — exiting)"
    exit 0
fi

# Results tracking
mkdir -p "$ROOT_DIR/findings"
REPORT_FILE="$ROOT_DIR/findings/.batch-report-$(date '+%Y%m%d-%H%M%S').txt"
echo "Hornet Batch Report — $(date)" > "$REPORT_FILE"
echo "Duration per harness: $DURATION ($DURATION_SECS seconds)" >> "$REPORT_FILE"
echo "Cores: $CORES, Memory limit: ${MEMORY_LIMIT}MB/instance" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

BATCH_START=$(date +%s)

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_SKIP_BIN_CHECK=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
# Per-instance AFL_TMPDIR root. Each parallel instance gets its own subdir under
# here ($AFL_TMP_BASE/<harness>/<instance>); a shared dir makes secondaries abort
# because AFL refuses to start when <AFL_TMPDIR>/.cur_input already exists. Must
# be under /tmp — /mnt/c can't ftruncate.
AFL_TMP_BASE="${AFL_TMPDIR_BASE:-/tmp/afl-tmp}"
export AFL_NO_UI=1
export DOTNET_TieredCompilation=0
export DOTNET_ReadyToRun=0

# Kill any stray AFL++ or dotnet processes from previous runs.
# Only kills processes owned by the current user.
cleanup_processes() {
    local killed=0

    # Kill afl-fuzz instances
    if pkill -u "$(id -u)" -f "afl-fuzz" 2>/dev/null; then
        killed=1
    fi

    # Kill orphaned dotnet processes running harness DLLs
    if pkill -u "$(id -u)" -f "dotnet.*Harness\." 2>/dev/null; then
        killed=1
    fi

    # Kill orphaned self-contained harness processes
    if pkill -u "$(id -u)" -f "publish/Harness\." 2>/dev/null; then
        killed=1
    fi

    if [ "$killed" -eq 1 ]; then
        # Give processes time to exit
        sleep 2
        # Force-kill any survivors
        pkill -9 -u "$(id -u)" -f "afl-fuzz" 2>/dev/null || true
        pkill -9 -u "$(id -u)" -f "dotnet.*Harness\." 2>/dev/null || true
        pkill -9 -u "$(id -u)" -f "publish/Harness\." 2>/dev/null || true
        sleep 1
    fi

    # Drop filesystem caches to reclaim memory (best-effort, needs root)
    if [ -w /proc/sys/vm/drop_caches ]; then
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi

    # Clean up AFL++ temp files (per-instance tmpdirs + legacy shared staging file)
    rm -rf "$AFL_TMP_BASE"/* 2>/dev/null || true
    rm -f /tmp/.afl-* /tmp/.cur_input 2>/dev/null || true
}

run_harness() {
    local harness="$1"
    local corpus_dir="$ROOT_DIR/corpora/$(find_corpus "$harness")"
    local findings_dir="$ROOT_DIR/findings/$harness"
    local harness_dll="$ROOT_DIR/publish/$harness/$harness.dll"
    local log_dir="$findings_dir/.logs"

    mkdir -p "$findings_dir" "$log_dir"

    # Muxer launch for both publish shapes; the app host breaks the SharpFuzz fork server
    # on .NET 11 RC 1+ (see lib/afl-target.sh).
        afl_resolve_target "$harness"
    local target_cmd=("${TARGET_CMD[@]}")

    # Auto-detect dictionary
    local dict_args=()
    local dict_alias
    dict_alias="$(echo "$harness" | sed 's/^Harness\.//' | tr '[:upper:]' '[:lower:]')"
    if [ -f "$ROOT_DIR/dictionaries/$dict_alias.dict" ]; then
        dict_args=(-x "$ROOT_DIR/dictionaries/$dict_alias.dict")
    fi

    local pids=()

    # Per-instance AFL_TMPDIR root for this harness (cleared per instance below).
    local tmp_base="$AFL_TMP_BASE/$harness"

    # Launch main (with memory limit) in its own AFL_TMPDIR
    mkdir -p "$tmp_base/main"; rm -f "$tmp_base/main/.cur_input"
    AFL_TMPDIR="$tmp_base/main" \
        afl-fuzz -i "$corpus_dir" -o "$findings_dir" -t 5000 -m "$MEMORY_LIMIT" -M main \
        "${dict_args[@]}" -- "${target_cmd[@]}" \
        > "$log_dir/main.log" 2>&1 &
    pids+=($!)

    sleep 2

    # Launch secondaries, each in its own AFL_TMPDIR
    for i in $(seq 1 $((CORES - 1))); do
        mkdir -p "$tmp_base/secondary$i"; rm -f "$tmp_base/secondary$i/.cur_input"
        AFL_TMPDIR="$tmp_base/secondary$i" \
            afl-fuzz -i "$corpus_dir" -o "$findings_dir" -t 5000 -m "$MEMORY_LIMIT" -S "secondary$i" \
            "${dict_args[@]}" -- "${target_cmd[@]}" \
            > "$log_dir/secondary$i.log" 2>&1 &
        pids+=($!)
        sleep 1
    done

    # Mark the start of the timed run (the health check + wait both count toward it).
    local run_start
    run_start=$(date +%s)

    # --- Health check ---------------------------------------------------------
    # A harness that fails to start (SharpFuzz fork-server handshake failure, OOM
    # at init, broken self-contained publish, etc.) makes afl-fuzz hit PROGRAM
    # ABORT within a few seconds. Without this check the runner would blindly
    # sleep the whole duration and only reveal "0 execs" at the very end. Instead,
    # look after a short warmup: if main has already died — or fuzzer_stats exists
    # but shows zero execs — skip the harness now and reclaim the rest of the slot.
    local health_wait=20
    [ "$DURATION_SECS" -lt "$health_wait" ] && health_wait="$DURATION_SECS"
    sleep "$health_wait"

    local main_alive=0
    kill -0 "${pids[0]}" 2>/dev/null && main_alive=1
    local early_execs=0
    if [ -f "$findings_dir/main/fuzzer_stats" ]; then
        early_execs=$(grep "^execs_done" "$findings_dir/main/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    fi
    local failed=0
    if [ "$main_alive" -eq 0 ]; then
        failed=1   # main aborted — definitive
    elif [ -f "$findings_dir/main/fuzzer_stats" ] && [ "${early_execs:-0}" -eq 0 ]; then
        failed=1   # alive but stuck at zero execs
    fi
    if [ "$failed" -eq 1 ]; then
        echo "  ⚠ FAILED TO START — main $([ "$main_alive" -eq 0 ] && echo aborted || echo "alive but 0 execs") after ${health_wait}s; skipping." >&2
        # Pull the abort reason from AFL's log, stripping its embedded ANSI color
        # escapes (otherwise the unterminated color code bleeds into later output).
        grep -m1 "PROGRAM ABORT" "$log_dir/main.log" 2>/dev/null \
            | sed -E 's/\x1b\[[0-9;]*[mK]//g; s/^/      abort: /' >&2 || true
        echo "      see $log_dir/main.log" >&2
        for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
        wait 2>/dev/null || true
        echo "0|0|0|0|0|FAILED"
        return
    fi

    # --- Liveness-aware wait --------------------------------------------------
    # Sleep out the remainder of the duration in short chunks so we can bail early
    # if every instance dies mid-run (mass OOM, etc.) instead of waiting to the end.
    local run_end=$((run_start + DURATION_SECS))
    while [ "$(date +%s)" -lt "$run_end" ]; do
        local remaining=$(( run_end - $(date +%s) ))
        [ "$remaining" -le 0 ] && break
        sleep $(( remaining < 15 ? remaining : 15 ))
        local any_alive=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then any_alive=1; break; fi
        done
        if [ "$any_alive" -eq 0 ]; then
            echo "  ⚠ all instances exited after $(format_time $(( $(date +%s) - run_start ))) — ending harness early" >&2
            break
        fi
    done

    # Stop all instances gracefully
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Wait up to 10 seconds for graceful shutdown
    local waited=0
    while [ "$waited" -lt 10 ]; do
        local alive=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                alive=1
                break
            fi
        done
        [ "$alive" -eq 0 ] && break
        sleep 1
        waited=$((waited + 1))
    done

    # Force-kill any survivors
    for pid in "${pids[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true

    # Count results
    local crashes=0 paths=0 total_execs=0 max_speed=0 hangs=0
    for dir in "$findings_dir"/*/; do
        [ -d "$dir" ] || continue
        local instance
        instance=$(basename "$dir")
        [[ "$instance" == .* ]] && continue
        local c
        c=$(find "$dir/crashes" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        local q
        q=$(find "$dir/queue" -maxdepth 1 -type f 2>/dev/null | wc -l)
        local h
        h=$(find "$dir/hangs" -maxdepth 1 -type f ! -name "README.txt" 2>/dev/null | wc -l)
        crashes=$((crashes + c))
        paths=$((paths + q))
        hangs=$((hangs + h))

        # Aggregate exec stats from fuzzer_stats
        if [ -f "$dir/fuzzer_stats" ]; then
            local execs speed
            execs=$(grep "^execs_done" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
            speed=$(grep "^execs_per_sec" "$dir/fuzzer_stats" 2>/dev/null | head -1 | awk '{print $3}' | cut -d. -f1)
            total_execs=$((total_execs + ${execs:-0}))
            [ "${speed:-0}" -gt "$max_speed" ] 2>/dev/null && max_speed=$speed
        fi
    done

    echo "$crashes|$paths|$total_execs|$max_speed|$hangs"
}

# Clean up before starting — kill leftovers from previous aborted runs
echo "Cleaning up stale processes..."
cleanup_processes

# Main loop
for i in "${!HARNESSES[@]}"; do
    harness="${HARNESSES[$i]}"
    step=$((i + 1))

    start_time=$(date +%s)
    end_est=$(date -d "+${DURATION_SECS} seconds" '+%H:%M' 2>/dev/null || date -r $((start_time + DURATION_SECS)) '+%H:%M' 2>/dev/null || echo "?")
    echo "=== [$step/$TOTAL] $harness ($DURATION, $CORES cores) === started $(date '+%H:%M'), ETA $end_est"

    result=$(run_harness "$harness")
    crashes=$(echo "$result" | cut -d'|' -f1)
    paths=$(echo "$result" | cut -d'|' -f2)
    total_execs=$(echo "$result" | cut -d'|' -f3)
    peak_speed=$(echo "$result" | cut -d'|' -f4)
    hangs=$(echo "$result" | cut -d'|' -f5)
    status=$(echo "$result" | cut -d'|' -f6)

    elapsed=$(( $(date +%s) - start_time ))
    execs_k=$((total_execs / 1000))
    if [ "$status" = "FAILED" ]; then
        echo "  ✗ FAILED TO START in $(format_time $elapsed) — 0 execs, skipped (re-instrument $harness)"
    else
        echo "  Done in $(format_time $elapsed): $paths paths, $crashes crashes, $hangs hangs, ${execs_k}K execs, ~${peak_speed} exec/sec"
    fi

    # Auto-triage if crashes found
    if [ "$SKIP_TRIAGE" = false ] && [ "$crashes" -gt 0 ]; then
        echo "  Triaging crashes..."
        if "$SCRIPT_DIR/triage.sh" "$harness" > /dev/null 2>&1; then
            unique=$(find "$ROOT_DIR/findings/$harness/triage" -maxdepth 1 -name "*.info" 2>/dev/null | wc -l)
            echo "  Triage: $unique unique bugs"
            crashes_info="$crashes crashes ($unique unique)"
        else
            echo "  Triage failed"
            crashes_info="$crashes crashes"
        fi
    else
        crashes_info="$crashes crashes"
    fi

    # Auto-triage hangs (classify INFINITE / SLOW / FAST). Hang triage replays each
    # deduplicated hang standalone (up to CONFIRM_TIMEOUT each), so it must run before
    # cleanup_processes kills the harness. INFINITE inputs are the genuine DoS candidates.
    if [ "$SKIP_TRIAGE" = false ] && [ "$SKIP_HANG_TRIAGE" = false ] && [ "$hangs" -gt 0 ]; then
        echo "  Triaging hangs..."
        if "$SCRIPT_DIR/triage-hangs.sh" "$harness" > /dev/null 2>&1; then
            infinite=$(find "$ROOT_DIR/findings/$harness/triage/hangs" -maxdepth 1 -name "*.info" 2>/dev/null | wc -l)
            echo "  Hang triage: $infinite INFINITE (genuine non-terminating)"
            hangs_info="$hangs hangs ($infinite infinite)"
        else
            echo "  Hang triage failed"
            hangs_info="$hangs hangs"
        fi
    else
        hangs_info="$hangs hangs"
    fi

    # Log to report
    if [ "$status" = "FAILED" ]; then
        printf "%-30s  FAILED TO START (0 execs)  (%s)\n" "$harness" "$(format_time $elapsed)" >> "$REPORT_FILE"
    else
        printf "%-30s  %s paths, %s, %s, %sK execs, ~%s exec/sec  (%s)\n" "$harness" "$paths" "$crashes_info" "$hangs_info" "$execs_k" "$peak_speed" "$(format_time $elapsed)" >> "$REPORT_FILE"
    fi

    # Clean up between harnesses to prevent memory accumulation
    echo "  Cleaning up..."
    cleanup_processes
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
