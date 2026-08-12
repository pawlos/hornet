#!/usr/bin/env bash
# Run coverage-report.sh over every harness in HARNESSES.md and render a ranked index.
# Usage: ./scripts/coverage-sweep.sh [--max-inputs N] [--timeout SECONDS] [--index-only]
#
# A full sweep is long — roughly two hours for ~85 harnesses at the default 300-input
# cap — so it is resilient by design: one harness that hangs or fails must not stop it.
set -uo pipefail   # deliberately NOT -e: a failing harness is data, not a fatal error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

MAX_INPUTS=300
PER_HARNESS_TIMEOUT=900
INDEX_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --max-inputs) MAX_INPUTS="$2"; shift 2 ;;
        --timeout)    PER_HARNESS_TIMEOUT="$2"; shift 2 ;;
        --index-only) INDEX_ONLY=1; shift ;;
        --help) sed -n '2,4p' "$0"; exit 0 ;;
        *) echo "ERROR: unknown option: $1"; exit 1 ;;
    esac
done

OUT_DIR="$ROOT_DIR/findings/_sweep"
RESULTS="$OUT_DIR/results.tsv"
mkdir -p "$OUT_DIR"

mapfile -t HARNESSES < <(grep -F 'instrument.sh' "$ROOT_DIR/HARNESSES.md" \
    | grep -oP '^\| \K[A-Za-z0-9._]+' | sort -u)

if [ "$INDEX_ONLY" -eq 0 ]; then
    : > "$RESULTS"
    echo "=== sweep: ${#HARNESSES[@]} harnesses, --max-inputs $MAX_INPUTS, ${PER_HARNESS_TIMEOUT}s each ==="

    i=0
    for h in "${HARNESSES[@]}"; do
        i=$((i + 1))
        log="$OUT_DIR/$h.log"
        start=$(date +%s)

        timeout "$PER_HARNESS_TIMEOUT" "$SCRIPT_DIR/coverage-report.sh" "$h" \
            --max-inputs "$MAX_INPUTS" > "$log" 2>&1
        rc=$?
        [ "$rc" -eq 0 ] && status=ok || status="fail:$rc"
        dur=$(( $(date +%s) - start ))

        # coverage-report.py emits a SUMMARY tail: harness, library, hit, inst, pct, files, panels
        summary="$(grep -P '^SUMMARY\t' "$log" | tail -1)"
        library="$(cut -f3 <<<"$summary")"
        hit="$(cut -f4 <<<"$summary")"
        inst="$(cut -f5 <<<"$summary")"
        pct="$(cut -f6 <<<"$summary")"
        files="$(cut -f7 <<<"$summary")"
        panels="$(cut -f8 <<<"$summary")"
        inputs="$(grep -oP 'inputs  : \K\d+' "$log" | tail -1)"
        total="$(grep -oP 'inputs  : \d+ of \K\d+' "$log" | tail -1)"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$h" "$status" "${library:-?}" "${hit:-0}" "${inst:-0}" "${pct:-0}" \
            "${files:-0}" "${panels:-0}" "${inputs:-0}" "${total:-0}" "$dur" >> "$RESULTS"
        printf '[%2d/%d] %-32s %-9s %6s%%  files=%-4s panels=%-3s %ss\n' \
            "$i" "${#HARNESSES[@]}" "$h" "$status" "${pct:-0}" "${files:-0}" "${panels:-0}" "$dur"
    done
fi

if [ ! -s "$RESULTS" ]; then
    echo "ERROR: no results at $RESULTS — run without --index-only first"
    exit 1
fi

echo ""
echo "=== Rendering index ==="
python3 "$ROOT_DIR/tools/coverage-report.py" \
    --index-from "$RESULTS" \
    --output "$OUT_DIR/index.html" \
    --generated "$(date -u '+%Y-%m-%d %H:%M UTC')"

echo ""
echo "=== Done ==="
awk -F'\t' '{if($2=="ok") ok++; else fail++} END {printf "  %d ok, %d failed\n", ok+0, fail+0}' "$RESULTS"
echo "  $OUT_DIR/index.html"
