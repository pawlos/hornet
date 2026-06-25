using System.IO.Compression;
using DotNetFuzzing.Shared;
using SharpFuzz;

// ============================================================================
//  EXAMPLE: structure-aware fuzzing with FuzzReader
// ----------------------------------------------------------------------------
//  A ZIP file is a chain of local file headers, a central directory, and an
//  end-of-central-directory record — tied together by byte offsets, sizes, and
//  per-entry CRC-32s. Mutate a real ZIP at the byte level and almost every
//  change breaks an offset or a CRC, so the reader rejects the file before it
//  ever decompresses an entry. A byte-level fuzzer stalls at that gate.
//
//  The structure-aware fix (the "build-from-plan" pattern): treat the fuzzer's
//  bytes as a PLAN, not as a ZIP. FuzzReader decodes them into choices — how
//  many entries, each entry's name, whether it's stored or deflated, its bytes
//  — and we assemble a VALID container with correct offsets/sizes/CRCs. Every
//  input now clears the reader's structural checks and exercises the real work:
//  central-directory parsing, name decoding, and the inflate path.
//
//  This is the same helper (DotNetFuzzing.Shared.FuzzReader) the JOSE and Fonts
//  structure-aware harnesses use; only the artifact being built differs.
//
//  Build/run like any harness:
//    ./scripts/instrument.sh Example.StructureAwareZip System.IO.Compression.dll
//    ./scripts/fuzz-afl.sh   Example.StructureAwareZip corpora/<seed-dir>
// ============================================================================

Fuzzer.OutOfProcess.Run(stream =>
{
    HarnessHelpers.RunWithExceptionFilter(() =>
    {
        byte[] input;
        using (var ms = new MemoryStream())
        {
            stream.CopyTo(ms);
            input = ms.ToArray();
        }
        if (input.Length == 0) return;

        // 1. Bytes -> plan -> a structurally valid ZIP.
        byte[] zip = ZipBuilder.Build(new FuzzReader(input));

        // 2. Drive the target: enumerate the central directory and decompress each entry.
        using var src = new MemoryStream(zip);
        using var archive = new ZipArchive(src, ZipArchiveMode.Read);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            _ = entry.FullName;
            _ = entry.CompressedLength;
            using Stream es = entry.Open();
            es.CopyTo(Stream.Null);          // forces the inflate path for deflated entries
        }
    });
});

internal static class ZipBuilder
{
    private const uint LocalSig = 0x04034b50;
    private const uint CentralSig = 0x02014b50;
    private const uint EocdSig = 0x06054b50;

    public static byte[] Build(FuzzReader r)
    {
        int entryCount = r.Range(1, 8);
        var entries = new List<Entry>(entryCount);
        for (int i = 0; i < entryCount; i++)
        {
            byte[] name = r.Take(r.Range(1, 32));
            if (name.Length == 0) name = new[] { (byte)'f' };
            byte[] content = r.Take(r.Int(1024));
            bool deflate = r.Bool();            // mix stored + deflated so the inflater is reached
            entries.Add(new Entry(name, content, deflate));
        }

        using var ms = new MemoryStream();

        // --- local file headers + (possibly compressed) data ---
        foreach (var e in entries)
        {
            e.LocalHeaderOffset = (uint)ms.Position;
            byte[] stored = e.Deflate ? Deflate(e.Content) : e.Content;
            e.StoredBytes = stored;

            WriteU32(ms, LocalSig);
            WriteU16(ms, 20);                   // version needed
            WriteU16(ms, 0);                    // flags
            WriteU16(ms, e.Deflate ? 8 : 0);    // method: 8 = deflate, 0 = stored
            WriteU16(ms, 0);                    // mod time
            WriteU16(ms, 0);                    // mod date
            WriteU32(ms, e.Crc);
            WriteU32(ms, (uint)stored.Length);  // compressed size
            WriteU32(ms, (uint)e.Content.Length); // uncompressed size
            WriteU16(ms, e.Name.Length);        // name length
            WriteU16(ms, 0);                    // extra length
            ms.Write(e.Name);
            ms.Write(stored);
        }

        // --- central directory ---
        uint cdOffset = (uint)ms.Position;
        foreach (var e in entries)
        {
            WriteU32(ms, CentralSig);
            WriteU16(ms, 20);                   // version made by
            WriteU16(ms, 20);                   // version needed
            WriteU16(ms, 0);                    // flags
            WriteU16(ms, e.Deflate ? 8 : 0);    // method
            WriteU16(ms, 0);                    // mod time
            WriteU16(ms, 0);                    // mod date
            WriteU32(ms, e.Crc);
            WriteU32(ms, (uint)e.StoredBytes!.Length);
            WriteU32(ms, (uint)e.Content.Length);
            WriteU16(ms, e.Name.Length);        // name length
            WriteU16(ms, 0);                    // extra length
            WriteU16(ms, 0);                    // comment length
            WriteU16(ms, 0);                    // disk number start
            WriteU16(ms, 0);                    // internal attributes
            WriteU32(ms, 0);                    // external attributes
            WriteU32(ms, e.LocalHeaderOffset);  // local header offset
            ms.Write(e.Name);
        }
        uint cdSize = (uint)ms.Position - cdOffset;

        // --- end of central directory ---
        WriteU32(ms, EocdSig);
        WriteU16(ms, 0);                        // disk number
        WriteU16(ms, 0);                        // disk with central directory
        WriteU16(ms, entries.Count);            // entries on this disk
        WriteU16(ms, entries.Count);            // total entries
        WriteU32(ms, cdSize);
        WriteU32(ms, cdOffset);
        WriteU16(ms, 0);                        // comment length

        return ms.ToArray();
    }

    private static byte[] Deflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var ds = new DeflateStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            ds.Write(data);
        return ms.ToArray();
    }

    private sealed class Entry
    {
        public Entry(byte[] name, byte[] content, bool deflate)
        {
            Name = name;
            Content = content;
            Deflate = deflate;
            Crc = Crc32(content);
        }

        public byte[] Name { get; }
        public byte[] Content { get; }
        public bool Deflate { get; }
        public uint Crc { get; }
        public uint LocalHeaderOffset { get; set; }
        public byte[]? StoredBytes { get; set; }
    }

    private static void WriteU16(Stream s, int v)
    {
        s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8));   // little-endian (ZIP)
    }

    private static void WriteU32(Stream s, uint v)
    {
        s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8));
        s.WriteByte((byte)(v >> 16)); s.WriteByte((byte)(v >> 24));
    }

    private static readonly uint[] CrcTable = BuildCrcTable();

    private static uint[] BuildCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }

    private static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
            crc = CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFF;
    }
}
