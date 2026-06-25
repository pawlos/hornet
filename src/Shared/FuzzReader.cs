namespace DotNetFuzzing.Shared;

/// <summary>
/// A cursor over a raw fuzzer input that decodes it into <em>structured choices</em> —
/// the building block of structure-aware ("grammar-respecting") fuzzing harnesses.
///
/// <para>
/// Coverage-guided fuzzers (AFL++, libFuzzer) mutate a flat byte buffer. For formats
/// with a strict envelope — length prefixes, offset tables, checksums, or a nested
/// grammar — purely byte-level mutation rarely produces a structurally valid input, so
/// the fuzzer stalls at the parser's first validation gate and never reaches the logic
/// behind it. The fix is to stop treating the bytes as the artifact and start treating
/// them as a <em>plan</em>: read a few bytes to pick an enum, a few more for a length,
/// the rest for a payload, and assemble a well-formed artifact from those choices. The
/// fuzzer still drives exploration (flipping a "plan" byte flips a branch), but every
/// generated artifact clears the envelope.
/// </para>
///
/// <para>
/// This is the same idea as libFuzzer's <c>FuzzedDataProvider</c> and Rust's
/// <c>arbitrary</c> crate. Reads past the end of the input return deterministic zeros
/// rather than throwing, so a harness never has to length-check before reading.
/// </para>
///
/// <example>
/// <code>
/// var r = new FuzzReader(data);
/// var algorithm = r.Pick(new[] { "HS256", "RS256", "none" }); // enum-like choice
/// int count      = r.Range(0, 16);                            // bounded length
/// byte[] payload = r.Take(r.Int(256));                        // variable-length blob
/// </code>
/// </example>
/// </summary>
public sealed class FuzzReader
{
    private readonly byte[] _data;
    private int _pos;

    public FuzzReader(byte[] data) => _data = data ?? Array.Empty<byte>();

    /// <summary>Bytes not yet consumed.</summary>
    public int Remaining => Math.Max(0, _data.Length - _pos);

    /// <summary>True while input remains; once false, readers yield zeros.</summary>
    public bool HasMore => _pos < _data.Length;

    /// <summary>Next byte, or 0 once the input is exhausted.</summary>
    public byte Byte() => _pos < _data.Length ? _data[_pos++] : (byte)0;

    /// <summary>One bit of entropy as a bool.</summary>
    public bool Bool() => (Byte() & 1) == 1;

    /// <summary>Big-endian-ish 16-bit value from two bytes.</summary>
    public int U16() => Byte() | (Byte() << 8);

    /// <summary>32-bit value from four bytes (as a long to stay non-negative).</summary>
    public long U32() => Byte() | ((long)Byte() << 8) | ((long)Byte() << 16) | ((long)Byte() << 24);

    /// <summary>A value in <c>[0, modExclusive)</c>, or 0 if the bound is non-positive.</summary>
    public int Int(int modExclusive)
    {
        if (modExclusive <= 1) return 0;
        // Three bytes gives enough range for typical lengths/indices without draining input.
        int v = Byte() | (Byte() << 8) | (Byte() << 16);
        return v % modExclusive;
    }

    /// <summary>A value in <c>[minInclusive, maxInclusive]</c>.</summary>
    public int Range(int minInclusive, int maxInclusive)
    {
        if (maxInclusive <= minInclusive) return minInclusive;
        return minInclusive + Int(maxInclusive - minInclusive + 1);
    }

    /// <summary>An index in <c>[0, count)</c> from two bytes.</summary>
    public int PickIndex(int count) => count <= 1 ? 0 : U16() % count;

    /// <summary>One element chosen from <paramref name="options"/>.</summary>
    public T Pick<T>(IReadOnlyList<T> options) => options[PickIndex(options.Count)];

    /// <summary>
    /// Up to <paramref name="n"/> bytes (fewer if the input is exhausted). Never throws;
    /// returns an empty array when nothing remains.
    /// </summary>
    public byte[] Take(int n)
    {
        if (n <= 0) return Array.Empty<byte>();
        int avail = Math.Min(n, _data.Length - _pos);
        if (avail <= 0) return Array.Empty<byte>();
        var b = new byte[avail];
        Array.Copy(_data, _pos, b, 0, avail);
        _pos += avail;
        return b;
    }

    /// <summary>All remaining bytes.</summary>
    public byte[] TakeRest() => Take(Remaining);
}
