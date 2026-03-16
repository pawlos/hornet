using System.Text;
using System.Xml;

namespace DotNetFuzzing.Shared;

public static class HarnessHelpers
{
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
        // Check the full exception hierarchy — library-specific exceptions
        // (like JsonReaderException) inherit from these base types.
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
            || IsLibraryException(ex);
    }

    private static bool IsLibraryException(Exception ex)
    {
        // Check the full type hierarchy — e.g. YamlDotNet.Core.SyntaxErrorException
        // inherits from YamlException, so we need to walk up the chain.
        for (var type = ex.GetType(); type != null && type != typeof(Exception); type = type.BaseType)
        {
            var typeName = type.FullName ?? "";
            if (typeName.Contains("JsonException", StringComparison.Ordinal)
                || typeName.Contains("JsonReaderException", StringComparison.Ordinal)
                || typeName.Contains("YamlException", StringComparison.Ordinal)
                || typeName.Contains("CsvHelper", StringComparison.Ordinal)
                || typeName.Contains("ImageFormatException", StringComparison.Ordinal)
                || typeName.Contains("UnknownImageFormatException", StringComparison.Ordinal)
                || typeName.Contains("InvalidImageContentException", StringComparison.Ordinal)
                || typeName.Contains("MessagePackSerializationException", StringComparison.Ordinal)
                || typeName.Contains("ImageProcessingException", StringComparison.Ordinal)
                || typeName.Contains("TextureFormatException", StringComparison.Ordinal)
                || typeName.Contains("TextureProcessingException", StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
