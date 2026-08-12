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
    # CopyDebugSymbolFilesFromPackages brings a package's own .pdb along; without it
    # publish drops them and libraries that ship symbols (MimeKit, for one) would be
    # reported as having none.
    dotnet publish "$ROOT_DIR/src/$HARNESS" -c Release -o "$PUBLISH_DIR" -v quiet --nologo \
        /p:CopyDebugSymbolFilesFromPackages=true
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

# --- symbol acquisition -------------------------------------------------------
# Without a PDB, dotnet-coverage cannot instrument a module at all: the assembly
# is absent from the output rather than reported as 0%.
MISSING_SYMBOLS=""
if [ "$REGEN" -eq 0 ]; then
    echo ""
    echo "=== Symbols ==="
    for dll in $TARGET_DLLS; do
        dll_path="$PUBLISH_DIR/$dll"
        pdb_path="${dll_path%.dll}.pdb"

        if [ ! -f "$dll_path" ]; then
            echo "  $dll: NOT IN PUBLISH DIR — stale HARNESSES.md row?"
            MISSING_SYMBOLS="$MISSING_SYMBOLS $dll"
            continue
        fi
        if [ -f "$pdb_path" ]; then
            echo "  $dll: pdb already present"
            continue
        fi
        if strings "$dll_path" | grep -q "EmbeddedPortablePdb"; then
            echo "  $dll: embedded pdb"
            continue
        fi

        if dotnet-symbol --symbols --output "$PUBLISH_DIR" "$dll_path" >/dev/null 2>&1 \
           && [ -f "$pdb_path" ]; then
            echo "  $dll: pdb from microsoft symbol server"
            continue
        fi
        if dotnet-symbol --symbols --output "$PUBLISH_DIR" \
               --server-path https://symbols.nuget.org/download/symbols/ \
               "$dll_path" >/dev/null 2>&1 && [ -f "$pdb_path" ]; then
            echo "  $dll: pdb from nuget symbol server"
            continue
        fi

        echo "  $dll: NO SYMBOLS — assembly will be absent from the report"
        MISSING_SYMBOLS="$MISSING_SYMBOLS $dll"
    done
fi

# --- replay under dotnet-coverage ---------------------------------------------
mkdir -p "$OUT_DIR"
if [ "$REGEN" -eq 0 ]; then
    REPLAY_SH="$(mktemp)"
    cat > "$REPLAY_SH" <<EOF
#!/usr/bin/env bash
# env -u __AFL_SHM_ID is required: with it set, the harness tries to speak AFL's
# fork-server protocol instead of reading one input from stdin.
while IFS= read -r f; do
    env -u __AFL_SHM_ID "$APPHOST" "$APPHOST.dll" < "\$f" >/dev/null 2>&1 || true
done < "$INPUT_LIST"
EOF
    chmod +x "$REPLAY_SH"

    echo ""
    echo "=== Replaying $INPUT_USED inputs under dotnet-coverage ==="
    dotnet-coverage collect \
        --output "$COBERTURA" --output-format cobertura \
        -- "$REPLAY_SH"
fi

if [ ! -s "$COBERTURA" ]; then
    echo "ERROR: no coverage produced at $COBERTURA"
    exit 1
fi

# A total absence of coverage means a broken pipeline (missing symbols, R2R not
# disabled, wrong publish), not a harness that covers nothing. Never report it
# as a result.
COVERED=$(python3 - "$COBERTURA" <<'PY'
import sys, xml.etree.ElementTree as ET
t = ET.parse(sys.argv[1])
print(sum(1 for c in t.getroot().iter('line') if int(c.get('hits', '0')) > 0))
PY
)
echo "  covered line records: $COVERED"
if [ "$COVERED" -eq 0 ]; then
    echo "ERROR: zero coverage across all targets — the pipeline is broken, not the harness."
    echo "  check: DOTNET_ReadyToRun=0 exported, PDBs present, publish-cov not instrumented"
    exit 1
fi

# --- render -------------------------------------------------------------------
# The packaged version is what was actually compiled into the assembly, so prefer
# it over whatever runtime happens to be installed. HARNESSES.md records "(BCL/SDK)"
# for shared-framework targets, which carry no package version of their own.
RUNTIME_TAG=""
if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    RUNTIME_TAG="v$VERSION"
else
    TFM="$(grep -oP '(?<=<TargetFramework>)[^<]+' "$ROOT_DIR/src/$HARNESS"/*.csproj | head -1 || true)"
    MAJOR="${TFM#net}"; MAJOR="${MAJOR%%.*}"
    if [ -n "$MAJOR" ]; then
        RT="$(dotnet --list-runtimes | awk -v m="$MAJOR" '$1=="Microsoft.NETCore.App" && $2 ~ "^"m"\\." {v=$2} END{print v}')"
        [ -n "$RT" ] && RUNTIME_TAG="v$RT"
    fi
fi

echo ""
echo "=== Rendering ==="
python3 "$ROOT_DIR/tools/coverage-report.py" \
    --cobertura "$COBERTURA" \
    --harness "$HARNESS" \
    --library "$LIBRARY" \
    --output "$OUT_DIR/coverage-report.html" \
    --inputs-used "$INPUT_USED" \
    --inputs-total "$INPUT_TOTAL" \
    --missing-symbols "$MISSING_SYMBOLS" \
    --runtime-tag "$RUNTIME_TAG" \
    --fuzzer-stats "$ROOT_DIR/findings/$HARNESS/default/fuzzer_stats"

echo ""
echo "=== Done ==="
echo "  $OUT_DIR/coverage-report.html"
