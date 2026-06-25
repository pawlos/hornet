# Structure-aware fuzzing

Coverage-guided fuzzers (AFL++, libFuzzer) mutate a flat byte buffer. That works well for permissive formats where almost any byte string is "valid enough" to drive the parser deep. It works *badly* for formats with a strict envelope — length prefixes, offset tables, checksums, or a nested grammar — because a random mutation breaks the envelope, the parser rejects the input at its first validation gate, and the code behind the gate is never reached. The fuzzer spends millions of executions bouncing off the front door.

**Structure-aware fuzzing** fixes this by changing what the bytes *mean*. Instead of treating the fuzzer's bytes as the artifact, treat them as a **plan**: read a few bytes to choose an enum, a few more for a length, the rest for a payload, then assemble a well-formed artifact from those choices. The fuzzer still drives exploration — flipping a "plan" byte flips a branch — but every artifact it produces clears the envelope and exercises real logic.

This is the same idea as libFuzzer's `FuzzedDataProvider`, Rust's `arbitrary` crate, and (for a full grammar) libprotobuf-mutator.

## When it helps — and when it doesn't

Structure-aware fuzzing is not a free upgrade. Its payoff depends on *why* the byte-level fuzzer is stuck:

- **Structural gate + large surface → big win.** Offset tables, length fields, checksums, and grammars are exactly what a byte-plan can satisfy by construction. If a large parser sits behind that gate, coverage jumps several-fold.
- **Cryptographic gate → limited win.** You cannot mutate past a MAC or signature. Structured inputs still dead-end at "authentication failed" unless the harness holds the keys and can mint genuinely valid inputs (see *round-trip* below).
- **Small target → small absolute win.** If the library's total reachable code is tiny, even full coverage isn't a big number.

A concrete illustration from this repo's harnesses, byte-level vs. structure-aware over comparable budgets:

| Target | Gate | Byte-level | Structure-aware | Note |
|--------|------|-----------|-----------------|------|
| JOSE (jose-jwt) | base64url + JSON envelope, then **AEAD** | 0.42% / 273 edges (83.5M execs) | 1.24% / 811 edges | small DLL; crypto gate needs round-trip mode to break |
| Fonts (sfnt TTF/OTF) | **table directory** (offsets/lengths) | 5.47% / 3,584 edges | 7.99% / 5,234 edges in 5 min | structural gate + large parser → fast, large jump |

The lesson: pick targets with a **structural** gate and a **large** parser behind it. JOSE was the most *starved* harness, but its gate is cryptographic and its DLL is small — the worst case, not the best.

## Two patterns

### 1. Build-from-plan

Assemble the whole artifact from `FuzzReader` choices. Best when the format is fully specified and cheap to emit (tokens, wire formats, small binary structures).

```csharp
var r = new FuzzReader(input);
var alg = r.Pick(new[] { "HS256", "RS256", "none" });   // enum-like choice
var header = $"{{\"alg\":\"{alg}\"}}";
string token = $"{B64Url(header)}.{B64Url(r.Take(r.Int(64)))}.{B64Url(r.Take(r.Int(64)))}";
Parser.Parse(token);                                     // always clears the envelope
```

### 2. Splice-and-fixup

Keep a known-good artifact as a *template*, let the fuzzer rewrite the interesting sub-parts, then re-serialize the container with offsets/lengths/checksums recomputed. Best for container formats with internal cross-references (fonts, archives, PE, media containers) that are tedious to build from scratch.

```csharp
// Parse a base font's table directory once, into { tag -> bytes }.
var tables = ParseSfnt(BaseFontBytes);

// Per iteration: rewrite a few tables' CONTENTS from the fuzzer's plan...
foreach (var i in PickTablesToEdit(r, tables))
    tables[i] = (tables[i].tag, r.Take(r.Int(4096)));

// ...then re-emit a VALID container (correct tags/offsets/lengths, 4-byte aligned).
byte[] font = BuildSfnt(version, tables);   // always parses past FontReader
Parser.Load(font);                          // cmap/glyf/name/GSUB parsers now reached
```

The container stays valid (it passes the directory gate every time), while the table *contents* are arbitrary — so the per-table parsers get hammered with hostile data they'd otherwise never see.

### Round-trip (for authenticated formats)

When the gate is cryptographic, the only way through is to let the harness produce *genuinely valid* inputs with keys it controls: `Encode` with a fixed key, then `Decode`. The decrypt/verify path succeeds, opening everything behind authentication (e.g. decompression of the plaintext). Use this *alongside* a forge mode — forge covers the envelope/parser-rejection paths, round-trip covers the post-authentication surface.

## The `FuzzReader` helper

`DotNetFuzzing.Shared.FuzzReader` (in `src/Shared/`) is the reusable byte-plan cursor. Reads past the end of the input return deterministic zeros, so a harness never has to length-check before reading.

| Method | Returns |
|--------|---------|
| `Byte()` | next byte (0 once exhausted) |
| `Bool()` | one bit as a bool |
| `U16()` / `U32()` | 16- / 32-bit value |
| `Int(modExclusive)` | value in `[0, mod)` |
| `Range(min, max)` | value in `[min, max]` |
| `PickIndex(count)` | index in `[0, count)` |
| `Pick(options)` | one element of a list |
| `Take(n)` | up to `n` bytes (fewer if exhausted) |
| `TakeRest()` | all remaining bytes |
| `Remaining` / `HasMore` | input left |

## Wiring it into a harness

A structure-aware harness is an ordinary SharpFuzz harness — only the first step changes (bytes → artifact):

```csharp
Fuzzer.OutOfProcess.Run(stream =>
{
    HarnessHelpers.RunWithExceptionFilter(() =>
    {
        byte[] input = ReadAll(stream);
        if (input.Length == 0) return;

        var artifact = Builder.Build(new FuzzReader(input));   // the structure-aware step
        Target.Parse(artifact);                                // exercise the library
    });
});
```

Then instrument and run with the usual project scripts:

```bash
./scripts/instrument.sh <Harness> <target.dll>
./scripts/fuzz-afl.sh <Harness> corpora/<dir>
```

Seed the corpus with a handful of small, varied byte files — they are *plans*, not literal artifacts, so any bytes work; the fuzzer discovers which plan-bytes matter from the coverage feedback.

## Caveats

- **You constrain what you can find.** A builder that always emits a valid table directory will never find a bug *in the directory parser*. Keep a byte-level harness running too — the two are complementary, not a replacement. (This repo runs structure-aware variants side-by-side with the originals for exactly this reason.)
- **Log any silent cap.** If the builder bounds a length, recursion depth, or count for throughput, say so — otherwise a whole class of inputs is silently out of scope.
- **Throughput vs. depth.** Structured inputs often cost more per execution (real crypto, decompression, larger artifacts). Coverage-per-execution is the metric that matters, not raw exec/sec.
