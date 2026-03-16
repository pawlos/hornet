# Hornet

Coverage-guided fuzzing framework for .NET libraries using [SharpFuzz](https://github.com/Metalnem/sharpfuzz) and [AFL++](https://github.com/AFLplusplus/AFLplusplus). Discover vulnerabilities in .NET/C# code — memory safety issues, denial-of-service bugs, parser crashes, and more.

## How It Works

```
[Seed Corpus] → [AFL++ mutator] → [stdin] → [.NET Harness] → [SharpFuzz coverage] → [AFL++ feedback loop]
```

1. **SharpFuzz** rewrites target DLL IL to insert coverage instrumentation (branch tracing)
2. **AFL++** generates mutated inputs and feeds them to the harness via stdin
3. The harness calls the target library with each input and catches expected exceptions
4. SharpFuzz reports coverage back to AFL++ via shared memory
5. AFL++ uses the coverage map to guide mutations toward new code paths
6. Inputs that cause **unexpected** exceptions (real bugs) are saved as crashes

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| .NET SDK | 10.0+ | `dotnet --version` to check |
| AFL++ | 4.x | `apt install afl++` or build from source |
| Linux | WSL2 or native | AFL++ requires Linux |

### Installing .NET 10

```bash
# If not already installed:
curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir "$HOME/.dotnet"
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"
```

## Quick Start

```bash
# 1. Install tools (one-time setup)
./tools/install-tools.sh

# 2. Build the solution
dotnet build -c Release

# 3. Publish + instrument a harness
./scripts/instrument.sh DemoHarness Newtonsoft.Json.dll

# 4. Start fuzzing
./scripts/fuzz-afl.sh DemoHarness corpora/demo
```

AFL++ will display a status screen showing paths discovered, exec/sec, and any crashes found. Press `Ctrl+C` to stop.

## Project Structure

```
dotnet-fuzzing/
├── dotnet-fuzzing.sln
├── global.json
├── src/
│   ├── Shared/                    # Common helpers for all harnesses
│   │   ├── Shared.csproj
│   │   └── HarnessHelpers.cs      # Exception filter (swallow expected, surface real bugs)
│   ├── DemoHarness/               # Example: fuzz Newtonsoft.Json
│   │   ├── DemoHarness.csproj
│   │   └── Program.cs
│   └── Harness.Template/         # Skeleton for your own harness
│       ├── Harness.Template.csproj
│       └── Program.cs
├── corpora/                       # Seed inputs for each target
│   └── demo/                      # JSON seeds for DemoHarness
├── dictionaries/                  # AFL++ dictionaries for better mutations
│   ├── json.dict
│   └── xml.dict
├── scripts/
│   ├── instrument.sh              # Publish + strip R2R + instrument target DLLs
│   ├── fuzz-afl.sh                # Run AFL++ against an instrumented harness
│   ├── fuzz-multi.sh              # Multi-core fuzzing (1 main + N secondaries)
│   ├── fuzz-batch.sh              # Batch fuzz all harnesses sequentially
│   ├── triage.sh                  # Deduplicate and classify crashes
│   └── monitor-crashes.sh         # Watch for new crashes across all harnesses
├── tools/
│   ├── install-tools.sh           # Install SharpFuzz CLI tool
│   └── StripR2R/                  # Helper to strip ReadyToRun native code from DLLs
├── publish/                       # (generated) Published harness binaries
└── findings/                      # (generated) AFL++ output (crashes, queue, stats)
```

## Writing a New Harness

### 1. Create the project

```bash
mkdir -p src/Harness.MyTarget
```

```xml
<!-- src/Harness.MyTarget/Harness.MyTarget.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="SharpFuzz" Version="2.2.0" />
    <PackageReference Include="SomeTarget.Library" Version="1.2.3" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\Shared\Shared.csproj" />
  </ItemGroup>
</Project>
```

### 2. Write the harness

```csharp
// src/Harness.MyTarget/Program.cs
using DotNetFuzzing.Shared;
using SharpFuzz;

Fuzzer.OutOfProcess.Run(stream =>
{
    HarnessHelpers.RunWithExceptionFilter(() =>
    {
        // Call the target library with the fuzzed input.
        // The stream contains AFL++'s mutated data.
        SomeTarget.Library.Parse(stream);
    });
});
```

Key points:
- Use `Fuzzer.OutOfProcess.Run` — it handles the AFL++ fork server protocol
- Wrap the target call in `HarnessHelpers.RunWithExceptionFilter` to suppress expected parsing exceptions
- Only **unexpected** exceptions (real bugs) will be reported as crashes
- Exercise as many code paths as possible (parse, validate, transform, serialize)

### 3. Create seed corpus

```bash
mkdir -p corpora/mytarget
# Add minimal valid inputs that exercise different features:
echo '<minimal valid input>' > corpora/mytarget/seed1.bin
echo '<another variant>'     > corpora/mytarget/seed2.bin
```

Good seeds are **small** (under 1KB), **valid** (pass normal parsing), and **diverse** (cover different features/formats).

### 4. Add to the solution

```bash
dotnet sln add src/Harness.MyTarget/Harness.MyTarget.csproj
```

### 5. Instrument and fuzz

```bash
./scripts/instrument.sh Harness.MyTarget SomeTarget.Library.dll
./scripts/fuzz-afl.sh Harness.MyTarget corpora/mytarget
```

## Included Harnesses

| Harness | Target Library | Instrument Command | Corpus |
|---------|---------------|-------------------|--------|
| DemoHarness | Newtonsoft.Json | `./scripts/instrument.sh DemoHarness Newtonsoft.Json.dll` | `corpora/demo` |
| Harness.Template | *(your library)* | *(see below)* | *(your seeds)* |

Use `Harness.Template` as a starting point for your own targets.

## BCL-Only Targets (Self-Contained Publish)

Some BCL assemblies (e.g. `System.Formats.Tar`, `System.IO.Compression`) are **not available as NuGet packages**. With framework-dependent publish, the .NET host always loads the framework's uninstrumented copy, ignoring any local instrumented version.

The workaround is a **self-contained publish** — this bundles the runtime with the app so there's no shared framework to override the instrumented DLL.

### Workflow for BCL-only harnesses

```bash
# 1. Publish self-contained
dotnet publish src/Harness.Tar -c Release -o publish/Harness.Tar --self-contained -r linux-x64 /p:UseAppHost=true

# 2. Strip R2R via ildasm/ilasm roundtrip (Mono.Cecil can't handle composite R2R)
ILDASM="$HOME/.nuget/packages/runtime.linux-x64.microsoft.netcore.ildasm/10.0.3/runtimes/linux-x64/native/ildasm"
ILASM="$HOME/.nuget/packages/runtime.linux-x64.microsoft.netcore.ilasm/10.0.3/runtimes/linux-x64/native/ilasm"
TMP=$(mktemp -d)
"$ILDASM" -out="$TMP/assembly.il" publish/Harness.Tar/System.Formats.Tar.dll
sed -i 's/0x%016I64x/0x0000000000100000/g' "$TMP/assembly.il"
sed -i 's/\.corflags 0x0000000[cC]/\.corflags 0x00000001/' "$TMP/assembly.il"
"$ILASM" -dll -output=publish/Harness.Tar/System.Formats.Tar.dll "$TMP/assembly.il"
rm -rf "$TMP"

# 3. Instrument with SharpFuzz
sharpfuzz publish/Harness.Tar/System.Formats.Tar.dll

# 4. Fuzz (fuzz-afl.sh auto-detects self-contained)
./scripts/fuzz-afl.sh Harness.Tar corpora/tar
```

## Scripts Reference

### `scripts/instrument.sh <harness-name> [dll1 dll2 ...]`

Publishes a harness as framework-dependent and instruments the specified DLLs with SharpFuzz.

- For NuGet package DLLs: found automatically in the publish output
- For BCL (runtime) DLLs: copied from the shared framework, R2R-stripped, then instrumented
- Output goes to `publish/<harness-name>/`

```bash
# Instrument a NuGet package DLL
./scripts/instrument.sh Harness.MyTarget SomeLibrary.dll

# Instrument multiple DLLs
./scripts/instrument.sh Harness.MyTarget SomeLibrary.dll SomeLibrary.Core.dll
```

### `scripts/fuzz-afl.sh <harness-name> <corpus-dir> [extra-afl-args...]`

Launches AFL++ against an instrumented harness. Auto-detects self-contained vs framework-dependent publish (uses the native app host for self-contained, `dotnet` for framework-dependent).

- Findings are written to `findings/<harness-name>/`
- Crashes: `findings/<harness-name>/default/crashes/`
- Queue (coverage-increasing inputs): `findings/<harness-name>/default/queue/`

```bash
# Basic fuzzing
./scripts/fuzz-afl.sh DemoHarness corpora/demo

# With AFL++ dictionary for better mutations
./scripts/fuzz-afl.sh Harness.Json corpora/json -x dictionaries/json.dict

# Parallel fuzzing (master + secondary)
./scripts/fuzz-afl.sh MyHarness corpora/seeds -M master
./scripts/fuzz-afl.sh MyHarness corpora/seeds -S secondary1  # in another terminal
```

### `scripts/fuzz-multi.sh <harness-name> <corpus-dir> [--cores N]`

Launches multiple AFL++ instances in parallel (1 main + N-1 secondary) for maximum throughput. All instances share the same findings directory and sync test cases automatically.

- Default core count: half of available CPUs
- Logs per instance: `findings/<harness-name>/.logs/`
- Ctrl+C stops all instances and prints aggregated stats
- Use `afl-whatsup findings/<harness-name>` to check live progress

```bash
# Use default core count (half of available)
./scripts/fuzz-multi.sh Harness.MyTarget corpora/mytarget

# Specify core count
./scripts/fuzz-multi.sh Harness.MyTarget corpora/mytarget --cores 8
```

### `scripts/fuzz-batch.sh [options] [harness1 harness2 ...]`

Sequentially fuzzes all (or selected) harnesses with multi-core AFL++, auto-triaging after each. Ideal for overnight unattended runs.

- Default: all published harnesses, 2 hours each, quarter of available cores
- Produces a summary report at `findings/.batch-report-<timestamp>.txt`
- Ctrl+C stops the current harness and skips to shutdown
- Automatic process cleanup between harnesses to prevent memory accumulation
- Configurable per-instance memory limit (default 2GB)

```bash
# Fuzz everything overnight (2h each)
./scripts/fuzz-batch.sh

# Quick sweep — 30 min each
./scripts/fuzz-batch.sh --duration 30m

# Specific targets only
./scripts/fuzz-batch.sh --duration 1h Harness.MyTarget Harness.AnotherTarget

# Memory-constrained system
./scripts/fuzz-batch.sh --cores 2 --memory-limit 1024

# Preview without running
./scripts/fuzz-batch.sh --dry-run
```

### `scripts/triage.sh [harness-name]`

Replays crash inputs, deduplicates by exception type + stack location, and produces a triage report.

- If no harness name given, triages all harnesses with crashes
- Results are written to `findings/<harness-name>/triage/`
- Each unique crash gets: `.input` (raw crash), `.trace` (full output), `.info` (summary)
- Set `MINIMIZE=1` to run `afl-tmin` on each unique crash

```bash
# Triage all harnesses
./scripts/triage.sh

# Triage a specific harness
./scripts/triage.sh Harness.MyTarget

# Triage with minimization
MINIMIZE=1 ./scripts/triage.sh Harness.MyTarget
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOTNET_ROOT` | `$HOME/.dotnet` | Path to .NET SDK installation |
| `AFL_NO_UI` | `0` | Set to `1` for headless mode (CI, logging) |
| `MINIMIZE` | `0` | Set to `1` to minimize crashes during triage |

## Examining Findings

When AFL++ finds a crash:

```bash
# List crash inputs
ls findings/DemoHarness/default/crashes/

# Replay a crash to see the exception
dotnet publish/DemoHarness/DemoHarness.dll < findings/DemoHarness/default/crashes/id:000000,...

# Minimize a crash input (smaller = easier to analyze)
afl-tmin -i findings/DemoHarness/default/crashes/id:000000,... \
         -o minimized.bin \
         -- $HOME/.dotnet/dotnet publish/DemoHarness/DemoHarness.dll
```

## Exception Filtering

`HarnessHelpers.RunWithExceptionFilter` suppresses exceptions that represent **normal input rejection** (not bugs):

- `FormatException`, `ArgumentException` — malformed input
- `InvalidOperationException` — invalid state from bad input
- `XmlException`, `JsonReaderException` — parser rejections
- `IOException`, `EndOfStreamException` — truncated input
- `OverflowException` — numeric overflow from fuzzed values
- Library-specific exceptions (detected by type name)

Exceptions that are **not** filtered (real bugs that surface as crashes):

- `OutOfMemoryException` — DoS via memory exhaustion
- `StackOverflowException` — DoS via unbounded recursion
- `IndexOutOfRangeException` — potential out-of-bounds access
- `NullReferenceException` — null pointer dereference
- `AccessViolationException` — memory corruption
- Any other unexpected exception

## Troubleshooting

See [docs/afl-troubleshooting.md](docs/afl-troubleshooting.md) for common AFL++ errors and warnings when fuzzing .NET targets, with fixes.

## Technical Notes

### ReadyToRun (R2R) Assemblies

.NET ships runtime DLLs with ReadyToRun pre-compiled native code. SharpFuzz requires pure IL assemblies for instrumentation. The `tools/StripR2R` helper uses Mono.Cecil to re-write DLLs as pure IL.

Note: .NET 10 BCL assemblies use **composite R2R** format which Mono.Cecil cannot handle. For these, use the **ildasm/ilasm roundtrip** to strip R2R (see [BCL-Only Targets](#bcl-only-targets-self-contained-publish) above). BCL DLLs available as NuGet packages (e.g. `System.Formats.Cbor`) work with the standard framework-dependent workflow. BCL DLLs without NuGet packages (e.g. `System.Formats.Tar`) require self-contained publish.

### SharpFuzz Coverage Model

SharpFuzz inserts coverage instrumentation at the IL level (similar to AFL's compile-time instrumentation for C/C++). It uses a shared memory region to communicate edge coverage to AFL++. The `Fuzzer.OutOfProcess.Run` method implements the fork server protocol.

### Performance Tips

- Keep seed corpus inputs **small** (< 1KB) for faster exec/sec
- Use `AFL_NO_UI=1` when running in background or CI
- Run parallel instances with `-M`/`-S` flags for better throughput
- A good target: 500+ exec/sec; if much lower, check for I/O or allocation bottlenecks in the harness
