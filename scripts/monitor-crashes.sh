#!/usr/bin/env bash
# Monitor AFL++ crash directories for new/interesting crashes.
# Replays each crash, deduplicates by stack trace, and filters known bugs.
# Usage: ./scripts/monitor-crashes.sh [--watch INTERVAL] [harness-name]
#   --watch 5m    Watch mode: re-check every 5 minutes (supports s/m/h suffixes)
#   If harness-name is omitted, checks all harnesses.
# Examples:
#   ./scripts/monitor-crashes.sh                          # one-shot, all harnesses
#   ./scripts/monitor-crashes.sh Harness.ImageSharp       # one-shot, one harness
#   ./scripts/monitor-crashes.sh --watch 5m               # watch all, every 5 min
#   ./scripts/monitor-crashes.sh --watch 2m Harness.Pkcs  # watch one, every 2 min
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

# Parse arguments
WATCH_MODE=0
WATCH_INTERVAL=600  # default 10 minutes
HARNESS_FILTER=""
TIMEOUT=10  # seconds per replay

while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch)
            WATCH_MODE=1
            if [[ -n "${2:-}" ]]; then
                interval_str="$2"
                # Parse interval: 30s, 5m, 1h, or plain number (seconds)
                if [[ "$interval_str" =~ ^([0-9]+)s$ ]]; then
                    WATCH_INTERVAL="${BASH_REMATCH[1]}"
                elif [[ "$interval_str" =~ ^([0-9]+)m$ ]]; then
                    WATCH_INTERVAL=$(( ${BASH_REMATCH[1]} * 60 ))
                elif [[ "$interval_str" =~ ^([0-9]+)h$ ]]; then
                    WATCH_INTERVAL=$(( ${BASH_REMATCH[1]} * 3600 ))
                elif [[ "$interval_str" =~ ^[0-9]+$ ]]; then
                    WATCH_INTERVAL="$interval_str"
                else
                    echo "Invalid interval: $interval_str (use 30s, 5m, 1h, or seconds)"
                    exit 1
                fi
                shift
            fi
            shift
            ;;
        *)
            HARNESS_FILTER="$1"
            shift
            ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Known bugs database — each entry is "ExceptionType|StackFragment"
# These are bugs already reported or otherwise accounted for.
# Add entries here to suppress known bugs from the monitor output.
# Format: "ExceptionType|PartialStackFrame"
KNOWN_BUGS=(
    # Example:
    # "DivideByZeroException|SomeLibrary.SomeMethod"
    # "NullReferenceException|AnotherLibrary.Parse"
)

is_known_bug() {
    local exception_type="$1"
    local bug_location="$2"

    for known in "${KNOWN_BUGS[@]}"; do
        local known_type="${known%%|*}"
        local known_fragment="${known#*|}"
        if [[ "$exception_type" == *"$known_type"* && "$bug_location" == *"$known_fragment"* ]]; then
            return 0
        fi
    done
    return 1
}

# State file for watch mode — tracks what we've already alerted on
STATE_FILE="$ROOT_DIR/findings/.monitor-state"

load_seen_signatures() {
    declare -gA SEEN_SIGS
    if [ -f "$STATE_FILE" ]; then
        while IFS= read -r line; do
            SEEN_SIGS["$line"]=1
        done < "$STATE_FILE"
    fi
}

save_seen_signature() {
    echo "$1" >> "$STATE_FILE"
}

# Harnesses that had new bugs in the last scan (populated by run_scan)
HARNESSES_WITH_NEW_BUGS=()

# Run a single scan across all (or filtered) harnesses
# Returns 0 if new bugs found, 1 if nothing new
run_scan() {
    local total_new=0
    local total_known=0
    local total_hangs_new=0
    HARNESSES_WITH_NEW_BUGS=()

    for findings_dir in "$ROOT_DIR"/findings/*/; do
        local harness_name
        harness_name=$(basename "$findings_dir")

        if [ -n "$HARNESS_FILTER" ] && [ "$harness_name" != "$HARNESS_FILTER" ]; then
            continue
        fi

        if [ ! -d "$findings_dir/default/crashes" ] && [ ! -d "$findings_dir/default/hangs" ]; then
            continue
        fi

        local crashes_dir="$ROOT_DIR/findings/$harness_name/default/crashes"
        local hangs_dir="$ROOT_DIR/findings/$harness_name/default/hangs"
        local publish_dir="$ROOT_DIR/publish/$harness_name"
        local harness_dll="$publish_dir/$harness_name.dll"

        # Count crash files
        local crash_files=()
        if [ -d "$crashes_dir" ]; then
            while IFS= read -r -d '' f; do
                crash_files+=("$f")
            done < <(find "$crashes_dir" -maxdepth 1 -type f ! -name "README*" -print0 2>/dev/null | sort -z)
        fi

        # Count hang files
        local hang_count=0
        if [ -d "$hangs_dir" ]; then
            hang_count=$(find "$hangs_dir" -maxdepth 1 -type f ! -name "README*" 2>/dev/null | wc -l)
        fi

        if [ ${#crash_files[@]} -eq 0 ] && [ "$hang_count" -eq 0 ]; then
            continue
        fi

        if [ ! -f "$harness_dll" ]; then
            echo -e "${YELLOW}$harness_name: ${#crash_files[@]} crash(es), $hang_count hang(s) — cannot replay (not published)${NC}"
            continue
        fi

        # Determine how to run the harness
        local target_cmd
        if [ -f "$publish_dir/libcoreclr.so" ]; then
            target_cmd=("$publish_dir/$harness_name" "$harness_dll")
        else
            target_cmd=("$DOTNET" "$harness_dll")
        fi

        # Replay and classify each crash
        declare -A seen_signatures
        local new_bugs=()
        local known_count=0

        for crash_file in "${crash_files[@]}"; do
            local output
            output=$(timeout "$TIMEOUT" "${target_cmd[@]}" < "$crash_file" 2>&1) || true

            local exception_type
            if echo "$output" | grep -q "Out of memory"; then
                exception_type="OutOfMemoryException"
            else
                exception_type=$(echo "$output" | grep -o '[A-Za-z.]*Exception' | head -1)
            fi
            if [ -z "$exception_type" ]; then
                exception_type="Unknown"
            fi

            local bug_location
            bug_location=$(echo "$output" | grep '^ *at ' | grep -v -e 'HarnessHelpers\.' -e 'SharpFuzz\.' -e 'Fuzzer\.' -e 'Program\.' | head -1 | sed 's/^ *at //' | sed 's/ in .*//')
            if [ -z "$bug_location" ]; then
                bug_location=$(echo "$output" | grep '^ *at ' | head -1 | sed 's/^ *at //' | sed 's/ in .*//')
            fi
            if [ -z "$bug_location" ]; then
                bug_location="no-stack"
            fi

            local signature="${harness_name}|${exception_type}|${bug_location}"

            if [ -n "${seen_signatures[$signature]+x}" ]; then
                continue
            fi
            seen_signatures[$signature]=1

            # In watch mode, skip signatures we've already alerted on
            if [ "$WATCH_MODE" -eq 1 ] && [ -n "${SEEN_SIGS[$signature]+x}" ]; then
                if is_known_bug "$exception_type" "$bug_location"; then
                    known_count=$((known_count + 1))
                    total_known=$((total_known + 1))
                fi
                continue
            fi

            if is_known_bug "$exception_type" "$bug_location"; then
                known_count=$((known_count + 1))
                total_known=$((total_known + 1))
                # Record in watch state so we don't re-check next time
                if [ "$WATCH_MODE" -eq 1 ]; then
                    SEEN_SIGS["$signature"]=1
                    save_seen_signature "$signature"
                fi
            else
                total_new=$((total_new + 1))
                new_bugs+=("$exception_type|$bug_location|$(basename "$crash_file")|$(wc -c < "$crash_file")")
                # Record in watch state
                if [ "$WATCH_MODE" -eq 1 ]; then
                    SEEN_SIGS["$signature"]=1
                    save_seen_signature "$signature"
                fi
            fi
        done

        # Check hangs
        local new_hang_count=0
        if [ "$hang_count" -gt 0 ]; then
            local hang_files=()
            while IFS= read -r -d '' f; do
                hang_files+=("$f")
            done < <(find "$hangs_dir" -maxdepth 1 -type f ! -name "README*" -print0 2>/dev/null | sort -z)

            declare -A hang_sigs
            for hang_file in "${hang_files[@]}"; do
                if ! timeout 2 "${target_cmd[@]}" < "$hang_file" >/dev/null 2>&1; then
                    local exit_code=$?
                    if [ "$exit_code" -eq 124 ]; then
                        local sig="hang|$harness_name"
                        if [ -z "${hang_sigs[$sig]+x}" ]; then
                            hang_sigs[$sig]=1

                            local watch_sig="$harness_name|HANG|infinite-loop"
                            if [ "$WATCH_MODE" -eq 1 ] && [ -n "${SEEN_SIGS[$watch_sig]+x}" ]; then
                                known_count=$((known_count + 1))
                                total_known=$((total_known + 1))
                                continue
                            fi

                            new_hang_count=$((new_hang_count + 1))
                            total_hangs_new=$((total_hangs_new + 1))

                            if [ "$WATCH_MODE" -eq 1 ]; then
                                SEEN_SIGS["$watch_sig"]=1
                                save_seen_signature "$watch_sig"
                            fi
                        fi
                    fi
                fi
            done
        fi

        # Output for this harness
        local new_count=${#new_bugs[@]}
        local status_color="$GREEN"
        local marker=""
        if [ "$new_count" -gt 0 ] || [ "$new_hang_count" -gt 0 ]; then
            status_color="$RED"
            marker=" ← INVESTIGATE"
        fi

        echo -e "${status_color}${harness_name}: ${#crash_files[@]} crash(es), $hang_count hang(s) — $known_count known, $new_count NEW, $new_hang_count new hang(s)${marker}${NC}"

        for bug_info in "${new_bugs[@]}"; do
            IFS='|' read -r ex_type location filename size <<< "$bug_info"
            echo -e "  ${RED}NEW${NC} ${YELLOW}$ex_type${NC}"
            echo -e "       at $location"
            echo -e "       file: $filename ($size bytes)"
        done

        if [ "$new_hang_count" -gt 0 ]; then
            echo -e "  ${RED}NEW HANG${NC} — process does not terminate (possible infinite loop)"
        fi

        # Track harnesses with new findings for auto-triage
        if [ "$new_count" -gt 0 ] || [ "$new_hang_count" -gt 0 ]; then
            HARNESSES_WITH_NEW_BUGS+=("$harness_name")
        fi
    done

    echo ""
    echo -e "${BOLD}=== Summary ===${NC}"
    if [ "$total_new" -eq 0 ] && [ "$total_hangs_new" -eq 0 ]; then
        echo -e "${GREEN}No new bugs found. $total_known known bug(s) suppressed. Keep fuzzing.${NC}"
    else
        echo -e "${RED}${BOLD}Found $total_new new crash(es) and $total_hangs_new new hang(s)!${NC} ($total_known known suppressed)"

        # Auto-triage harnesses with new bugs
        for h in "${HARNESSES_WITH_NEW_BUGS[@]}"; do
            echo ""
            echo -e "${BOLD}${CYAN}=== Auto-triage: $h ===${NC}"
            MINIMIZE=0 "$SCRIPT_DIR/triage.sh" "$h" 2>&1
        done
    fi

    [ "$total_new" -gt 0 ] || [ "$total_hangs_new" -gt 0 ]
}

# Format seconds to human-readable
format_interval() {
    local s=$1
    if [ "$s" -ge 3600 ]; then
        echo "$((s / 3600))h$((s % 3600 / 60))m"
    elif [ "$s" -ge 60 ]; then
        echo "$((s / 60))m"
    else
        echo "${s}s"
    fi
}

# Main
if [ "$WATCH_MODE" -eq 1 ]; then
    load_seen_signatures
    echo -e "${BOLD}${CYAN}=== Crash Monitor (watch mode — every $(format_interval $WATCH_INTERVAL)) ===${NC}"
    echo -e "${DIM}Press Ctrl+C to stop. State saved to findings/.monitor-state${NC}"
    echo ""

    # First run — full scan
    run_scan

    # Subsequent runs — only show new findings
    while true; do
        echo ""
        echo -e "${DIM}--- sleeping $(format_interval $WATCH_INTERVAL) (next check at $(date -d "+${WATCH_INTERVAL} seconds" '+%H:%M:%S' 2>/dev/null || date -v+${WATCH_INTERVAL}S '+%H:%M:%S' 2>/dev/null || echo '?')) ---${NC}"
        sleep "$WATCH_INTERVAL"

        echo ""
        echo -e "${BOLD}${CYAN}=== Crash Monitor — $(date '+%Y-%m-%d %H:%M:%S') ===${NC}"
        echo ""
        run_scan
    done
else
    echo -e "${BOLD}${CYAN}=== Crash Monitor ===${NC}"
    echo ""
    run_scan
fi
