#!/usr/bin/env bash
# Triage AFL++ crashes: replay, deduplicate by stack trace, and optionally minimize.
# Usage: ./scripts/triage.sh [harness-name]
#   If harness-name is omitted, triages all harnesses with crashes.
#   Results are written to findings/<harness>/triage/
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

HARNESS_FILTER="${1:-}"
MINIMIZE="${MINIMIZE:-0}"  # Set MINIMIZE=1 to run afl-tmin on unique crashes
TIMEOUT=10  # seconds per replay

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

triage_harness() {
    local harness_name="$1"
    local findings_base="$ROOT_DIR/findings/$harness_name"
    local triage_dir="$findings_base/triage"
    local publish_dir="$ROOT_DIR/publish/$harness_name"
    local harness_dll="$publish_dir/$harness_name.dll"

    # Collect crash files from all instances (default, main, secondary*)
    local crash_files=()
    for instance_dir in "$findings_base"/*/; do
        [ -d "$instance_dir/crashes" ] || continue
        local instance
        instance=$(basename "$instance_dir")
        [[ "$instance" == .* ]] && continue
        [[ "$instance" == "triage" ]] && continue
        while IFS= read -r -d '' f; do
            crash_files+=("$f")
        done < <(find "$instance_dir/crashes" -maxdepth 1 -type f ! -name "README*" -print0 2>/dev/null)
    done

    if [ ${#crash_files[@]} -eq 0 ]; then
        return
    fi

    echo -e "${CYAN}=== $harness_name: ${#crash_files[@]} crash(es) ===${NC}"

    if [ ! -f "$harness_dll" ]; then
        echo -e "  ${RED}Harness DLL not found: $harness_dll (run instrument.sh first)${NC}"
        return
    fi

    # Determine how to run the harness
    local target_cmd
    if [ -f "$publish_dir/libcoreclr.so" ]; then
        target_cmd=("$publish_dir/$harness_name" "$harness_dll")
    else
        target_cmd=("$DOTNET" "$harness_dll")
    fi

    mkdir -p "$triage_dir"

    # Replay each crash and capture the stack trace
    declare -A seen_signatures
    local unique_count=0
    local total=0

    for crash_file in "${crash_files[@]}"; do
        total=$((total + 1))
        local basename
        basename=$(basename "$crash_file")

        # Replay with timeout and capture output
        local output
        output=$(timeout "$TIMEOUT" "${target_cmd[@]}" < "$crash_file" 2>&1) || true

        # Extract exception type
        local exception_type
        if echo "$output" | grep -q "Out of memory"; then
            exception_type="OutOfMemoryException"
        else
            exception_type=$(echo "$output" | grep -o '[A-Za-z.]*Exception' | head -1)
        fi
        if [ -z "$exception_type" ]; then
            exception_type="Unknown"
        fi

        # Get the first stack frame that isn't harness/sharpfuzz boilerplate
        local bug_location
        bug_location=$(echo "$output" | grep '^ *at ' | grep -v -e 'HarnessHelpers\.' -e 'SharpFuzz\.' -e 'Fuzzer\.' | head -1 | sed 's/^ *at //' | sed 's/ in .*//')
        if [ -z "$bug_location" ]; then
            bug_location=$(echo "$output" | grep '^ *at ' | head -1 | sed 's/^ *at //' | sed 's/ in .*//')
        fi
        if [ -z "$bug_location" ]; then
            bug_location="no-stack"
        fi

        # Create a dedup signature from exception type + location
        local signature="${exception_type}|${bug_location}"

        if [ -z "${seen_signatures[$signature]+x}" ]; then
            seen_signatures[$signature]=1
            unique_count=$((unique_count + 1))
            local crash_id="crash_$(printf '%03d' $unique_count)"

            echo -e "  ${RED}[$crash_id]${NC} ${YELLOW}$exception_type${NC}"
            echo -e "         at ${bug_location}"
            echo -e "         file: $basename"
            echo -e "         size: $(wc -c < "$crash_file") bytes"

            # Save unique crash info
            cp "$crash_file" "$triage_dir/${crash_id}.input"
            echo "$output" > "$triage_dir/${crash_id}.trace"
            cat > "$triage_dir/${crash_id}.info" <<EOF
Exception: $exception_type
Location:  $bug_location
Source:    $basename
Size:      $(wc -c < "$crash_file") bytes

--- Full output ---
$output
EOF

            # Optionally minimize with afl-tmin
            if [ "$MINIMIZE" = "1" ]; then
                echo -e "         ${CYAN}minimizing...${NC}"
                local min_file="$triage_dir/${crash_id}.min"
                if timeout 120 afl-tmin \
                    -i "$crash_file" \
                    -o "$min_file" \
                    -t $((TIMEOUT * 1000)) \
                    -- "${target_cmd[@]}" >/dev/null 2>&1; then
                    local orig_size new_size
                    orig_size=$(wc -c < "$crash_file")
                    new_size=$(wc -c < "$min_file")
                    echo -e "         ${GREEN}minimized: $orig_size → $new_size bytes${NC}"
                else
                    echo -e "         ${YELLOW}minimization failed or timed out${NC}"
                fi
            fi
        else
            echo -e "  ${GREEN}[dup]${NC} $exception_type ($basename)"
        fi
    done

    echo -e "  ${GREEN}Summary: $unique_count unique bug(s) from ${#crash_files[@]} crash file(s)${NC}"
    echo -e "  Triage output: $triage_dir/"
    echo ""
}

echo -e "${CYAN}=== Crash Triage ===${NC}"
echo ""

found_any=0
for findings_dir in "$ROOT_DIR"/findings/*/; do
    harness_name=$(basename "$findings_dir")

    if [ -n "$HARNESS_FILTER" ] && [ "$harness_name" != "$HARNESS_FILTER" ]; then
        continue
    fi

    # Check all instance dirs (default, main, secondary*) for crashes
    crash_count=0
    for instance_dir in "$findings_dir"/*/; do
        [ -d "$instance_dir/crashes" ] || continue
        inst=$(basename "$instance_dir")
        [[ "$inst" == .* || "$inst" == "triage" ]] && continue
        c=$(find "$instance_dir/crashes" -maxdepth 1 -type f ! -name "README*" 2>/dev/null | wc -l)
        crash_count=$((crash_count + c))
    done
    if [ "$crash_count" -gt 0 ]; then
        found_any=1
        triage_harness "$harness_name"
    fi
done

if [ "$found_any" -eq 0 ]; then
    echo "No crashes found."
    if [ -n "$HARNESS_FILTER" ]; then
        echo "Checked: findings/$HARNESS_FILTER/*/crashes/"
    else
        echo "Checked: findings/*/*/crashes/"
    fi
fi
