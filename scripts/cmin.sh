#!/usr/bin/env bash
# Minimize a corpus with afl-cmin, launching the harness exactly as fuzz-afl.sh does.
# Usage: ./scripts/cmin.sh <harness-name> <corpus-dir> [out-dir]
#   out-dir defaults to <corpus-dir>-min and must not exist yet (or be empty).
# Env:
#   CMIN_TIMEOUT  per-exec timeout in ms (default 5000, same as fuzz-afl.sh)
#   CMIN_EDGES=1  pass -e (edge coverage only, ignore hit counts)
#   CMIN_CRASHES=1 pass -C (keep crashing inputs only)
# Example: ./scripts/cmin.sh Harness.HtmlSanitizer corpora/htmlsanitizer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck source=lib/afl-target.sh
source "$SCRIPT_DIR/lib/afl-target.sh"

USAGE="Usage: cmin.sh <harness-name> <corpus-dir> [out-dir]"
HARNESS_NAME="${1:?$USAGE}"
CORPUS_DIR="${2:?$USAGE}"
CORPUS_DIR="${CORPUS_DIR%/}"
OUT_DIR="${3:-$CORPUS_DIR-min}"
OUT_DIR="${OUT_DIR%/}"
[[ "$CORPUS_DIR" != /* ]] && CORPUS_DIR="$ROOT_DIR/$CORPUS_DIR"
[[ "$OUT_DIR" != /* ]] && OUT_DIR="$ROOT_DIR/$OUT_DIR"

TIMEOUT_MS="${CMIN_TIMEOUT:-5000}"

afl_resolve_target "$HARNESS_NAME"

if [ ! -f "$HARNESS_DLL" ]; then
    echo "ERROR: Harness DLL not found: $HARNESS_DLL"
    echo "Run: ./scripts/instrument.sh $HARNESS_NAME <dlls...>"
    exit 1
fi
if [ ! -d "$CORPUS_DIR" ]; then
    echo "ERROR: Corpus directory not found: $CORPUS_DIR"
    exit 1
fi
if [ -e "$OUT_DIR" ] && [ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then
    echo "ERROR: Output directory exists and is not empty: $OUT_DIR"
    exit 1
fi

# Own AFL_TMPDIR, so a cmin run never clears the .cur_input of a fuzzer running on the
# same harness out of /tmp/afl-tmp/<harness>.
export AFL_TMPDIR="${AFL_TMPDIR:-${AFL_TMPDIR_BASE:-/tmp/afl-tmp}/$HARNESS_NAME.cmin}"
afl_export_env "$HARNESS_NAME"
# afl-cmin refuses -i/-o under /tmp without this; the staging dir below lives there.
export AFL_ALLOW_TMP=1

CMIN_FLAGS=()
[ "${CMIN_EDGES:-0}" = "1" ] && CMIN_FLAGS+=(-e)
[ "${CMIN_CRASHES:-0}" = "1" ] && CMIN_FLAGS+=(-C)

# afl-cmin writes its traces and a stdin staging file into <out>/.traces; keep that on
# /tmp (/mnt/c can't ftruncate and hardlinks are unreliable there), then copy the result.
STAGE="$(mktemp -d "${AFL_TMPDIR}/cmin.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

count_files() { find "$1" -maxdepth 1 -type f ! -name '.*' | wc -l; }
BEFORE=$(count_files "$CORPUS_DIR")
BEFORE_BYTES=$(find "$CORPUS_DIR" -maxdepth 1 -type f ! -name '.*' -printf '%s\n' | awk '{s+=$1} END {print s+0}')

echo "=== afl-cmin ($HARNESS_KIND) ==="
echo "Harness: ${TARGET_CMD[*]}"
echo "Corpus:  $CORPUS_DIR"
echo "Output:  $OUT_DIR"
echo "Timeout: ${TIMEOUT_MS} ms${CMIN_FLAGS[*]:+  flags: ${CMIN_FLAGS[*]}}"
echo ""

afl-cmin -i "$CORPUS_DIR" -o "$STAGE/out" -t "$TIMEOUT_MS" -m none "${CMIN_FLAGS[@]}" \
    -- "${TARGET_CMD[@]}"

mkdir -p "$OUT_DIR"
find "$STAGE/out" -maxdepth 1 -type f ! -name '.*' -exec cp -t "$OUT_DIR" {} +

AFTER=$(count_files "$OUT_DIR")
AFTER_BYTES=$(find "$OUT_DIR" -maxdepth 1 -type f ! -name '.*' -printf '%s\n' | awk '{s+=$1} END {print s+0}')
echo ""
echo "Before: $BEFORE files, $BEFORE_BYTES bytes"
echo "After:  $AFTER files, $AFTER_BYTES bytes  ($OUT_DIR)"
if [ "$AFTER" -eq 0 ]; then
    echo "ERROR: minimized corpus is empty"
    exit 1
fi
