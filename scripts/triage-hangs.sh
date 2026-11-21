#!/usr/bin/env bash
# Triage AFL++ hangs: verify which are genuine non-terminating hangs vs slow-but-finite,
# deduplicate by ancestry, and report per-harness.
#
# Usage: ./scripts/triage-hangs.sh [harness-name]
#   If harness-name is omitted, triages all harnesses with hang files.
#   Results are written to findings/<harness>/triage/hangs/
#
# Classification:
#   INFINITE  — did not terminate within CONFIRM_TIMEOUT (genuine DoS candidate)
#   SLOW      — terminated between AFL_TIMEOUT and CONFIRM_TIMEOUT (slow-but-finite)
#   FAST      — terminated within AFL_TIMEOUT (false positive; AFL flake)
#
# Environment overrides:
#   AFL_TIMEOUT=5        seconds (AFL's hang threshold; inputs faster than this are false positives)
#   CONFIRM_TIMEOUT=60   seconds (inputs still running after this are classified INFINITE)
#   MINIMIZE=1           run afl-tmin on INFINITE inputs
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"
# shellcheck source=lib/afl-target.sh
source "$SCRIPT_DIR/lib/afl-target.sh"

HARNESS_FILTER="${1:-}"
AFL_TIMEOUT="${AFL_TIMEOUT:-5}"
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-60}"
MINIMIZE="${MINIMIZE:-0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

triage_hangs_harness() {
    local harness_name="$1"
    local findings_base="$ROOT_DIR/findings/$harness_name"
    local triage_dir="$findings_base/triage/hangs"
    local publish_dir="$ROOT_DIR/publish/$harness_name"
    local harness_dll="$publish_dir/$harness_name.dll"

    # Collect hang files from all instances (default, main, secondary*)
    local hang_files=()
    for instance_dir in "$findings_base"/*/; do
        [ -d "$instance_dir/hangs" ] || continue
        local instance
        instance=$(basename "$instance_dir")
        [[ "$instance" == .* ]] && continue
        [[ "$instance" == "triage" ]] && continue
        while IFS= read -r -d '' f; do
            hang_files+=("$f")
        done < <(find "$instance_dir/hangs" -maxdepth 1 -type f ! -name "README*" -print0 2>/dev/null)
    done

    if [ ${#hang_files[@]} -eq 0 ]; then
        return
    fi

    echo -e "${CYAN}=== $harness_name: ${#hang_files[@]} hang(s) ===${NC}"

    if [ ! -f "$harness_dll" ]; then
        echo -e "  ${RED}Harness DLL not found: $harness_dll (run instrument.sh first)${NC}"
        return
    fi

    # Launch as fuzz-afl.sh does (muxer for both publish shapes; see lib/afl-target.sh).
    afl_resolve_target "$harness_name"
    local target_cmd=("${TARGET_CMD[@]}")

    mkdir -p "$triage_dir"

    # Dedup by src ancestry: AFL embeds src:NNNNNN in the filename.
    # Multiple hangs with the same immediate source seed are variants of the same root input.
    # We keep one representative per unique src cluster (the smallest file in each cluster).
    declare -A src_seen        # src_id -> smallest file path
    declare -A src_smallest    # src_id -> smallest size

    for hang_file in "${hang_files[@]}"; do
        local basename
        basename=$(basename "$hang_file")
        # Extract first src id from filename, e.g. src:000344+000008 -> 000344
        local src_id
        src_id=$(echo "$basename" | grep -oE 'src:[0-9]+' | head -1 | tr -d 'src:')
        src_id="${src_id:-unknown}"

        local sz
        sz=$(wc -c < "$hang_file")

        if [ -z "${src_seen[$src_id]+x}" ] || [ "$sz" -lt "${src_smallest[$src_id]}" ]; then
            src_seen[$src_id]="$hang_file"
            src_smallest[$src_id]="$sz"
        fi
    done

    local n_clusters=${#src_seen[@]}
    echo -e "  ${CYAN}Deduplicated to $n_clusters src cluster(s) from ${#hang_files[@]} file(s) — testing one per cluster${NC}"
    echo -e "  Thresholds: AFL=${AFL_TIMEOUT}s  CONFIRM=${CONFIRM_TIMEOUT}s"
    echo ""

    local infinite_count=0 slow_count=0 fast_count=0 hang_idx=0

    for src_id in $(echo "${!src_seen[@]}" | tr ' ' '\n' | sort); do
        hang_file="${src_seen[$src_id]}"
        local basename
        basename=$(basename "$hang_file")
        local sz
        sz=$(wc -c < "$hang_file")
        hang_idx=$((hang_idx + 1))

        # Run with CONFIRM_TIMEOUT; measure wall time
        local start_ns end_ns elapsed_ms rc
        start_ns=$(date +%s%N)
        timeout "$CONFIRM_TIMEOUT" "${target_cmd[@]}" < "$hang_file" >/dev/null 2>&1
        rc=$?
        end_ns=$(date +%s%N)
        elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

        local class label color
        if [ "$rc" -eq 124 ]; then
            # Did not terminate within CONFIRM_TIMEOUT
            class="INFINITE"
            label="INFINITE (>${CONFIRM_TIMEOUT}s)"
            color="$RED"
            infinite_count=$((infinite_count + 1))
        elif [ "$elapsed_ms" -gt $((AFL_TIMEOUT * 1000)) ]; then
            class="SLOW"
            label="SLOW     (${elapsed_ms}ms, finite)"
            color="$YELLOW"
            slow_count=$((slow_count + 1))
        else
            class="FAST"
            label="FAST     (${elapsed_ms}ms, false positive)"
            color="$GREEN"
            fast_count=$((fast_count + 1))
        fi

        echo -e "  [${color}${class}${NC}] src:${src_id}  ${elapsed_ms}ms  ${sz}B  ${basename:0:40}"

        # Save INFINITE inputs for further analysis
        if [ "$class" = "INFINITE" ]; then
            local hang_id
            hang_id="hang_$(printf '%03d' $infinite_count)"
            cp "$hang_file" "$triage_dir/${hang_id}.input"
            cat > "$triage_dir/${hang_id}.info" <<EOF
Class:   INFINITE (did not terminate within ${CONFIRM_TIMEOUT}s)
Source:  $basename
Size:    ${sz} bytes
SrcId:   $src_id

Run standalone to verify (outside AFL):
  timeout 120 ${target_cmd[*]} < $triage_dir/${hang_id}.input
EOF
            echo -e "         saved → ${triage_dir}/${hang_id}.input"

            # Optional: minimize with afl-tmin (--hang mode)
            if [ "$MINIMIZE" = "1" ]; then
                echo -e "         ${CYAN}minimizing (hang mode)...${NC}"
                local min_file="$triage_dir/${hang_id}.min"
                if AFL_SKIP_BIN_CHECK=1 AFL_SKIP_CPUFREQ=1 \
                   timeout 180 afl-tmin \
                       -i "$hang_file" \
                       -o "$min_file" \
                       -t $((CONFIRM_TIMEOUT * 1000)) \
                       -- "${target_cmd[@]}" >/dev/null 2>&1; then
                    local new_size
                    new_size=$(wc -c < "$min_file")
                    echo -e "         ${GREEN}minimized: ${sz} → ${new_size} bytes${NC}"
                else
                    echo -e "         ${YELLOW}minimization failed or timed out${NC}"
                fi
            fi
        fi
    done

    echo ""
    echo -e "  ${BLUE}Summary: ${RED}${infinite_count} INFINITE${NC}  ${YELLOW}${slow_count} SLOW${NC}  ${GREEN}${fast_count} FAST${NC}  (from $n_clusters clusters / ${#hang_files[@]} total files)"
    echo -e "  Triage output: $triage_dir/"
    echo ""
}

echo -e "${CYAN}=== Hang Triage ===${NC}"
echo -e "  AFL_TIMEOUT=${AFL_TIMEOUT}s  CONFIRM_TIMEOUT=${CONFIRM_TIMEOUT}s"
echo ""

found_any=0
for findings_dir in "$ROOT_DIR"/findings/*/; do
    harness_name=$(basename "$findings_dir")

    if [ -n "$HARNESS_FILTER" ] && [ "$harness_name" != "$HARNESS_FILTER" ]; then
        continue
    fi

    # Check all instance dirs for hang files
    hang_count=0
    for instance_dir in "$findings_dir"/*/; do
        [ -d "$instance_dir/hangs" ] || continue
        inst=$(basename "$instance_dir")
        [[ "$inst" == .* || "$inst" == "triage" ]] && continue
        c=$(find "$instance_dir/hangs" -maxdepth 1 -type f ! -name "README*" 2>/dev/null | wc -l)
        hang_count=$((hang_count + c))
    done
    if [ "$hang_count" -gt 0 ]; then
        found_any=1
        triage_hangs_harness "$harness_name"
    fi
done

if [ "$found_any" -eq 0 ]; then
    echo "No hang files found."
    if [ -n "$HARNESS_FILTER" ]; then
        echo "Checked: findings/$HARNESS_FILTER/*/hangs/"
    else
        echo "Checked: findings/*/*/hangs/"
    fi
fi
