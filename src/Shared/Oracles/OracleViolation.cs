namespace DotNetFuzzing.Shared.Oracles;

/// <summary>
/// Thrown when a target violates an invariant it documents — a configured limit that did not
/// hold, or a filtered member that turned out to be reachable. Distinct from a crash: nothing
/// faulted, the target simply did not do what it promised.
/// </summary>
public sealed class OracleViolation : Exception
{
    public OracleViolation(string invariant, string detail)
        : base($"{invariant}: {detail}")
    {
        Invariant = invariant;
    }

    public string Invariant { get; }
}
