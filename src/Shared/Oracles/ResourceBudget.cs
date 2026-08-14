using System.Diagnostics;

namespace DotNetFuzzing.Shared.Oracles;

/// <summary>
/// Measures wall clock and thread-local allocation across a guarded call. Deliberately not
/// disposable and not callback-based: the measurement has to be readable after the guarded
/// call returns *and* after it throws.
/// </summary>
public sealed class ResourceBudget
{
    private readonly long _startTimestamp;
    private readonly long _startAllocated;

    public ResourceBudget()
    {
        // Same counter Jint's MemoryLimitConstraint uses, so comparisons against LimitMemory
        // are exact rather than approximate, and unaffected by machine load.
        _startAllocated = GC.GetAllocatedBytesForCurrentThread();
        _startTimestamp = Stopwatch.GetTimestamp();
    }

    public TimeSpan Elapsed => Stopwatch.GetElapsedTime(_startTimestamp);

    public long Allocated => GC.GetAllocatedBytesForCurrentThread() - _startAllocated;
}
