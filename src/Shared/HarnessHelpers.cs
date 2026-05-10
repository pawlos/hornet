using System.Text;
using System.Xml;

namespace DotNetFuzzing.Shared;

public static class HarnessHelpers
{
    // Substring patterns the harness has registered as benign — see
    // AddExpectedExceptionPatterns. Mutated only at startup (single-threaded,
    // before Fuzzer.OutOfProcess.Run), so a plain List is fine.
    private static readonly List<string> _registeredPatterns = new();

    /// <summary>
    /// Register substring patterns that mark an exception as expected/benign.
    /// During filtering, the type-name hierarchy of each thrown exception is
    /// walked and matched (StringComparison.Ordinal) against these patterns.
    /// Call once at startup, before <see cref="SharpFuzz.Fuzzer.OutOfProcess.Run"/>.
    /// </summary>
    public static void AddExpectedExceptionPatterns(params string[] typeNameSubstrings)
    {
        foreach (var pattern in typeNameSubstrings)
        {
            if (!string.IsNullOrEmpty(pattern))
                _registeredPatterns.Add(pattern);
        }
    }

    /// <summary>
    /// Wraps a fuzzing action, filtering out expected/benign exceptions
    /// so only unexpected crashes surface to AFL++ as findings.
    /// </summary>
    public static void RunWithExceptionFilter(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex) when (IsExpectedException(ex))
        {
            // Swallow expected exceptions — these are normal parsing rejections,
            // not bugs. AFL++ only sees crashes (unhandled exceptions).
        }
    }

    /// <summary>
    /// Returns true for exceptions that are normal/expected behavior
    /// when parsing untrusted input. These are NOT bugs.
    /// </summary>
    public static bool IsExpectedException(Exception ex)
    {
        // Generic base types — these cover the common parser-rejection idioms
        // every input-driven library uses (FormatException, ArgumentException,
        // OverflowException, IOException…). Library-specific exception types
        // are matched via patterns registered with AddExpectedExceptionPatterns.
        return ex is FormatException
            or ArgumentException       // includes ArgumentNull, ArgumentOutOfRange
            or InvalidOperationException
            or XmlException
            or NotSupportedException
            or OverflowException
            or InvalidDataException
            or IOException             // includes EndOfStreamException
            or ObjectDisposedException
            or DecoderFallbackException
            or System.Runtime.Serialization.SerializationException
            or KeyNotFoundException
            or UriFormatException
            || MatchesRegisteredPattern(ex);
    }

    private static bool MatchesRegisteredPattern(Exception ex)
    {
        if (_registeredPatterns.Count == 0) return false;

        // Walk the full type hierarchy — e.g. YamlDotNet.Core.SyntaxErrorException
        // inherits from YamlException, so a pattern on the base type matches.
        for (var type = ex.GetType(); type != null && type != typeof(Exception); type = type.BaseType)
        {
            var typeName = type.FullName ?? "";
            foreach (var pattern in _registeredPatterns)
            {
                if (typeName.Contains(pattern, StringComparison.Ordinal))
                    return true;
            }
        }
        return false;
    }
}
