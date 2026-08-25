# SharpFuzz Instrumentation — How This Project Instruments DLLs

## TL;DR

Instrumentation is a two-stage pipeline: **(1) strip ReadyToRun native code** so only pure MSIL
remains, then **(2) let upstream SharpFuzz rewrite that IL** to inject AFL++ coverage. Stage 1 is our
own code; stage 2 is stock SharpFuzz. The "two ways" people remember are both stage-1 R2R strippers,
selected by **try-then-fallback**, not by a DLL-type check.

## The two R2R-stripping paths (stage 1)

Both remove the R2R native payload; they differ only in the tool. The script always tries Cecil first
and reaches the ildasm/ilasm roundtrip only when Cecil exits non-zero (`scripts/instrument.sh:110`).
There is no "is this a BCL DLL?" probe anywhere.

**Path 1 — Mono.Cecil (default, tried first)**
- Tool: `tools/StripR2R/Program.cs:24-30` — `AssemblyDefinition.ReadAssembly` then write it back;
  Cecil's re-write drops the R2R native code, leaving pure IL.
- Invoked at `scripts/instrument.sh:110`: `dotnet run --project "$STRIP_R2R_DIR" -c Release -- "$dll_path"`.
- Works on normal third-party DLLs (Newtonsoft, ImageSharp).

**Path 2 — ildasm/ilasm IL roundtrip (fallback)**
- `strip_via_ilasm`, `scripts/instrument.sh:33-58`: disassemble to text IL with `ildasm` (:47),
  sed-patch two ilasm incompatibilities, reassemble a pure-IL DLL with `ilasm -dll` (:54).
  - `sed 's/0x%016I64x/0x0000000000100000/g'` (:50) — fixes a bad hex format string ildasm emits.
  - `sed 's/\.corflags 0x0000000[cC]/\.corflags 0x00000001/'` (:51) — clears the mixed-mode/native
    corflags bits so the output is marked pure-IL.
- `ildasm`/`ilasm` come from pinned NuGet native packages (`scripts/instrument.sh:28-29`,
  `runtime.linux-x64.microsoft.netcore.ildasm/ilasm 10.0.3`).

**Why the fallback exists:** .NET 8+ BCL DLLs ship as **composite R2R** (several assemblies fused into
one native image). Mono.Cecil can't parse that, so its write throws and Path 1 fails; the ildasm/ilasm
roundtrip drops to textual IL and back, avoiding Cecil entirely. In practice normal third-party DLLs
succeed on Path 1; composite-R2R `System.*` DLLs fall to Path 2 — but the selection is purely the
Cecil exit code, not a classification.

## Is the strip always run?

Yes — unconditional. The only guard around the block is "does the file exist"
(`scripts/instrument.sh:107`, `if [ -f "$dll_path" ]`). There is no ReadyToRun-header detection.

On an **already-pure-IL DLL** (no R2R payload), Path 1 is a harmless read-then-write roundtrip:
`StripR2R/Program.cs:24-30` reads and writes it back regardless, succeeds with nothing to strip, so the
ildasm/ilasm fallback never fires. It is a no-op in effect but not skipped.

Caveat: because the Cecil roundtrip is unconditional, the assembly is still rewritten even when there is
nothing to remove — this can drop a strong-name signature, etc. Inherent to the roundtrip, not gated.

## What actually does the instrumentation (stage 2)

**Upstream SharpFuzz — not our code.** The injection is `sharpfuzz "$dll_path"`
(`scripts/instrument.sh:116`), the **SharpFuzz.CommandLine** global tool installed by
`tools/install-tools.sh` (`dotnet tool install --global SharpFuzz.CommandLine`). That CLI calls into
SharpFuzz's own IL rewriter (`SharpFuzz.Fuzzer.Instrument`). No custom instrumenter exists in this repo —
everything in `tools/` is StripR2R + seed generators; none of it injects coverage.

What SharpFuzz injects: it walks every method body and, at each basic block / branch target, inserts IL
that updates AFL++'s 64 KB shared-memory coverage bitmap using the classic afl edge scheme
(`bitmap[prev_loc ^ cur_loc]++; prev_loc = cur_loc >> 1`). Standard coverage-guided fuzzing behavior.

## Runtime side

Harnesses call upstream `Fuzzer.OutOfProcess.Run` directly (e.g. `src/DemoHarness/Program.cs:10`,
`src/Harness.AngleSharp/Program.cs`, `src/Example.StructureAwareZip/Program.cs:29`; package
`SharpFuzz 2.2.0`, `src/DemoHarness/DemoHarness.csproj:9`). `OutOfProcess.Run` stands up AFL's
forkserver handshake and the shared-memory link, then feeds each testcase to the instrumented DLL —
tying the stage-2 instrumentation to AFL's bitmap.

This is why any instrumented code that runs **before** `Fuzzer.OutOfProcess.Run` hits an access
violation (shared memory not yet mapped) — hence the CLAUDE.md `Lazy<T>` init-order rule: wrap
schema/validator/pipeline construction so it runs inside the fuzz lambda.

## instrument.sh pipeline (end to end)

1. **Build the stripper** (`:61-62`): `dotnet build tools/StripR2R -c Release`.
2. **Publish the harness** (`:66-73`): target DLLs deleted from the publish dir first (:67-69) so a fresh
   copy is written, then `dotnet publish "$HARNESS_DIR" -c Release -o "$PUBLISH_DIR" /p:UseAppHost=true`.
   Self-contained vs framework-dependent is driven by the harness csproj (RID/SelfContained) — the script
   passes neither flag; `UseAppHost=true` ensures a native launcher exists.
3. **Resolve the shared-framework dir** (`:79-91`) from the csproj `<TargetFramework>`; major version must
   match or you fuzz the wrong framework.
4. **Per-DLL loop** (`:95-120`): copy from the shared framework if a requested DLL is absent from publish
   (:102-105, framework-dependent only) → **strip R2R** via the try/fallback (:107-113) →
   **instrument** with `sharpfuzz "$dll_path"` (:116).

## Division of labor

- **This repo:** publish + R2R strip (`tools/StripR2R` Cecil path, `strip_via_ilasm` roundtrip) + seed
  generation.
- **Upstream SharpFuzz:** the actual coverage instrumentation (`sharpfuzz` CLI / `Fuzzer.Instrument`) and
  the forkserver runtime (`Fuzzer.OutOfProcess.Run`).

The strip step exists **only** because SharpFuzz's IL rewriter needs pure MSIL to operate on.

## Operational gotchas

- **Self-contained required** for shared-framework BCL targets (Tar, Compression, TextJson, Xml,
  ReflectionMetadata, Asn1, X509, NumberParsing) — set RID + SelfContained in the csproj, or the .NET host
  swaps your instrumented copy for a framework copy at runtime and it silently doesn't fuzz. These launch
  via the native app host (`publish/X/X`), not `dotnet X.dll`.
- **Multi-DLL targets** (e.g. HotChocolate) — pass all DLLs in one `instrument.sh` call; the `:95` loop
  handles them together.
- **WSL2** — AFL++ needs `AFL_TMPDIR=/tmp` (`/mnt/c/` can't `ftruncate`) and `AFL_SKIP_BIN_CHECK=1` (the
  `dotnet` host itself isn't instrumented). These live in the fuzz scripts, not `instrument.sh`.
- **Init order / `Lazy<T>`** — instrumented code must not run before `Fuzzer.OutOfProcess.Run`; an AV at
  process init means shared memory isn't set up yet, not a SharpFuzz bug.

## Key files

- `scripts/instrument.sh` — pipeline + both strip paths
- `tools/StripR2R/Program.cs` — Cecil R2R stripper (Path 1)
- `tools/install-tools.sh` — installs SharpFuzz.CommandLine, SDK/runtime, AFL++, coverage tools
