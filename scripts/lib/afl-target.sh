# Shared AFL++ launch logic for the project scripts. Source it; don't execute it.
#
#   source "$SCRIPT_DIR/lib/afl-target.sh"
#   afl_resolve_target <harness-name>   # sets HARNESS_DLL, HARNESS_PUBLISH_DIR, HARNESS_KIND, TARGET_CMD
#   afl_export_env <harness-name>       # exports the AFL++ / .NET env every AFL tool run needs
#
# Expects ROOT_DIR to be set by the caller.

export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"

afl_resolve_target() {
    local harness_name="$1"
    HARNESS_PUBLISH_DIR="$ROOT_DIR/publish/$harness_name"
    HARNESS_DLL="$HARNESS_PUBLISH_DIR/$harness_name.dll"

    # Both publish shapes are launched through the muxer, with the harness assembly as the
    # app path. A self-contained publish still runs self-contained that way — its
    # runtimeconfig.json carries "includedFrameworks", so hostfxr loads the app-local runtime
    # and the app-local instrumented BCL copies rather than the shared framework.
    #
    # The native app host cannot be used. SharpFuzz's out-of-process fork server re-launches
    # itself for each execution as `dotnet $(Environment.CommandLine)`, so argv[0] has to be
    # something the muxer accepts as an app path. Up to .NET 11 Preview 7 the host rewrote
    # argv[0] to the managed assembly path, which it does; .NET 11 RC 1 changed argv[0] to
    # report the host invocation name instead (dotnet/runtime#131671), so an app-host-launched
    # harness makes SharpFuzz spawn `dotnet /path/to/Harness.Name`, which the muxer reads as a
    # `dotnet-Harness.Name` tool command and fails to find. Every execution then looks to AFL
    # like a crash, and the dry run aborts with "We need at least one valid input seed".
    if [ -f "$HARNESS_PUBLISH_DIR/libcoreclr.so" ]; then
        HARNESS_KIND="self-contained"
    else
        HARNESS_KIND="framework-dependent"
    fi
    TARGET_CMD=("$DOTNET" "$HARNESS_DLL")
}

afl_export_env() {
    local harness_name="$1"
    export AFL_SKIP_CPUFREQ=1
    export AFL_SKIP_BIN_CHECK=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    # Dedicated per-harness AFL_TMPDIR. AFL stages the test case as
    # <AFL_TMPDIR>/.cur_input and aborts on startup if that file already exists, so a
    # leftover from a kill -9'd prior run would wedge the next run. Use a per-harness
    # dir (not bare /tmp) and clear any stale staging file before launch. Must be
    # under /tmp — /mnt/c can't ftruncate.
    export AFL_TMPDIR="${AFL_TMPDIR:-${AFL_TMPDIR_BASE:-/tmp/afl-tmp}/$harness_name}"
    mkdir -p "$AFL_TMPDIR"; rm -f "$AFL_TMPDIR/.cur_input"

    # Reduce .NET JIT non-determinism that causes AFL++ instability warnings
    export DOTNET_TieredCompilation=0
    export DOTNET_ReadyToRun=0
}
