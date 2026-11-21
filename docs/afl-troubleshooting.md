# AFL++ Troubleshooting

Common AFL++ errors and warnings when fuzzing .NET targets with SharpFuzz, and how to fix them.

## Errors

### "Hmm, your binary produced no instrumentation output"

```
[-] PROGRAM ABORT : No instrumentation detected
```

The target DLL was not instrumented with SharpFuzz, or the instrumented DLL isn't being loaded.

**Fix:**
1. Re-run `sharpfuzz <target.dll>` on the DLL in `publish/<Harness>/`
2. For self-contained harnesses, make sure you instrumented the copy in `publish/`, not the one in `bin/`
3. For framework-dependent harnesses targeting BCL DLLs (e.g. `System.Formats.Tar`), the .NET host ignores app-local copies and loads from the shared framework instead. Switch to self-contained publish (see README)

### "Oops, the program crashed with one of the test cases provided"

```
[-] Oops, the program crashed with one of the test cases provided.
    ...
    The current memory limit (X MB) is too low for this program
```

AFL++'s `-m` flag uses `setrlimit` to cap virtual memory. .NET allocates large virtual address spaces even when physical usage is low, so any `-m` value that's meaningfully restrictive will crash the runtime.

**Fix:** Use `-m none` (the default in `fuzz-afl.sh`). Do not pass `-m <value>` for .NET targets. If you need to limit memory, use `DOTNET_GCHeapHardLimit` environment variable instead:
```bash
# Limit .NET GC heap to 512MB
export DOTNET_GCHeapHardLimit=0x20000000
./scripts/fuzz-afl.sh Harness.MyTarget corpora/mytarget
```

### Every seed "results in a crash" on .NET 11 RC 1 or later

```
[!] WARNING: Test case 'id:000000,...' results in a crash, skipping
[+] All test cases processed.
[-] PROGRAM ABORT : We need at least one valid input seed that does not crash!
```

The fork server comes up, but every execution dies before the harness body runs. Adding logging to the fuzz lambda shows nothing, because the lambda is never reached.

This happens when an app-host-launched harness runs on .NET 11 RC 1 or later. SharpFuzz's out-of-process fork server relaunches the harness for each execution as `dotnet $(Environment.CommandLine)`. Through .NET 11 Preview 7 the host rewrote argv[0] to the managed assembly path, so the muxer received `dotnet /path/Harness.dll` and it worked. RC 1 changed argv[0] to report the host invocation name instead ([dotnet/runtime#131671](https://github.com/dotnet/runtime/pull/131671)), so the muxer now receives `dotnet /path/Harness` — no `.dll` — and reads it as a `dotnet-Harness` tool command.

`AFL_DEBUG=1` surfaces the muxer's own message, which is the only visible symptom:

```
Could not execute because the specified command or file was not found.
  * You intended to execute a .NET program, but dotnet-/path/publish/Harness/Harness does not exist.
```

**Fix:** launch through the muxer with the managed assembly as the app path, even for a self-contained publish. `fuzz-afl.sh` does this for every harness:

```bash
afl-fuzz ... -- "$DOTNET_ROOT/dotnet" /abs/path/publish/Harness/Harness.dll
```

A self-contained publish still runs self-contained this way — its `runtimeconfig.json` carries `includedFrameworks`, so `hostfxr` loads the app-local runtime and the app-local instrumented assemblies rather than the shared framework. Verified by coverage: the instrumented BCL copy is still the one that reports edges.

### "Fork server handshake failed"

```
[-] PROGRAM ABORT : Fork server handshake failed
```

The harness didn't start the SharpFuzz fork server.

**Fix:**
1. Verify the harness uses `Fuzzer.OutOfProcess.Run(...)` (not `Fuzzer.Run`)
2. Test manually: `echo "test" | dotnet publish/<Harness>/<Harness>.dll` — it should exit cleanly
3. For self-contained: `echo "test" | publish/<Harness>/<Harness>` (use the native host, not `dotnet`)
4. Check that `DOTNET_ROOT` is set correctly and the .NET SDK is installed

### "Unable to execute target application"

```
[-] PROGRAM ABORT : Unable to execute target application
```

AFL++ can't find or run the target binary.

**Fix:**
1. Check that the publish directory exists: `ls publish/<Harness>/`
2. For self-contained, ensure the native host is executable: `chmod +x publish/<Harness>/<Harness>`
3. Verify `DOTNET_ROOT` points to a valid .NET installation

### "AFL_TMPDIR is not a writable directory"

```
[-] PROGRAM ABORT : AFL_TMPDIR '/mnt/c/...' is not a writable directory
```

On WSL2, `/mnt/c/` (Windows filesystem) doesn't support `ftruncate`, which AFL++ needs.

**Fix:** Set `AFL_TMPDIR=/tmp` (already done by default in `fuzz-afl.sh`):
```bash
export AFL_TMPDIR=/tmp
```

### "can not use a+b mode on /mnt/c/..."

```
[-] PROGRAM ABORT : ftruncate() failed for shm
```

Same root cause as above — AFL++ shared memory can't be placed on a Windows-mounted filesystem.

**Fix:** `export AFL_TMPDIR=/tmp`

## Warnings

### "No new instrumentation output, test case may be useless"

```
[!] WARNING: No new instrumentation output, test case may be useless.
```

One or more seed inputs in the corpus don't trigger any new coverage beyond what other seeds already cover.

**Fix:** This is usually harmless — AFL++ will skip redundant seeds. But for better performance:
1. Remove duplicate or near-duplicate seeds from the corpus
2. Use `afl-cmin` to minimize the corpus, through the project script:
   ```bash
   scripts/cmin.sh <Harness> corpora/mytarget            # writes corpora/mytarget-min
   CMIN_TIMEOUT=10000 scripts/cmin.sh <Harness> corpora/mytarget /path/to/out
   ```
   It launches the harness exactly as `fuzz-afl.sh` does (muxer + harness `.dll`, same env: `AFL_SKIP_BIN_CHECK=1`, `AFL_TMPDIR` under `/tmp`, JIT knobs) via `scripts/lib/afl-target.sh`, and prints before/after file counts. `CMIN_EDGES=1` adds `-e`, `CMIN_CRASHES=1` adds `-C`. To pre-filter crash files before triage, use `CMIN=1 scripts/triage.sh <Harness>`.
3. Ensure seeds are small and diverse (different formats, features, edge cases)

### "Instability detected"

```
[!] WARNING: Stability issues detected, consider lowering AFL_FORKSRV_INIT_TMOUT
```

Or the stability percentage in the UI drops below 90%. This means the same input produces different coverage paths on repeated runs.

**Fix:** .NET JIT and tiered compilation cause non-determinism. `fuzz-afl.sh` already sets:
```bash
export DOTNET_TieredCompilation=0
export DOTNET_ReadyToRun=0
```
If stability is still low:
1. Avoid using `DateTime.Now`, `Random`, `Guid.NewGuid()`, or other non-deterministic APIs in the harness
2. Create objects/pipelines inside the `Fuzzer.OutOfProcess.Run` callback rather than outside it (e.g. Markdig's `MarkdownPipeline` must be created per-iteration)
3. Some instability (80-95%) is normal for .NET and doesn't significantly impact fuzzing effectiveness

### "Hmm, looks like the target binary terminated before we could complete a handshake"

```
[!] WARNING: Target binary terminated before completing handshake
```

The harness started but crashed or exited before the fork server was ready.

**Fix:**
1. Run manually: `echo "test" | dotnet publish/<Harness>/<Harness>.dll` and check for startup errors
2. Missing dependencies: `dotnet publish/<Harness>/<Harness>.dll` may print which DLL is missing
3. For HtmlSanitizer and similar: instrumented DLLs used during static initialization can cause `AccessViolationException` before the fork server starts — see README Special Cases section

### "All set and target map size ... is very small"

```
[*] All set and target map size is 128 (2^7), ...
```

Very low map size suggests only a tiny portion of the target is instrumented.

**Fix:**
1. Make sure you instrumented the right DLL (the library, not the harness itself)
2. Verify the harness actually calls into the target library — a missing `using` or wrong method call means the instrumented code is never reached
3. For multi-DLL targets, instrument all relevant DLLs: `./scripts/instrument.sh Harness.X Lib1.dll Lib2.dll`

### "Timeout while initializing fork server"

```
[!] WARNING: Timeout while initializing fork server (adjusting -t may help)
```

The harness takes too long to start up. .NET's JIT compilation on first run can be slow.

**Fix:** Increase the timeout:
```bash
./scripts/fuzz-afl.sh Harness.MyTarget corpora/mytarget -t 10000
```
The default in `fuzz-afl.sh` is `-t 5000` (5 seconds). For large targets or cold starts, try `-t 10000` or `-t 15000`.

### "cpu N seems idle, selecting it"

```
[*] Checking core_pattern...
[*] cpu 3 seems idle, selecting it
```

This is informational, not a warning. AFL++ is selecting which CPU core to pin to.

**No action needed.**
