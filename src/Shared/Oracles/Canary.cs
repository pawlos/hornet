namespace DotNetFuzzing.Shared.Oracles;

/// <summary>
/// Tripwire registered on an embedded scripting engine. <see cref="Allowed"/> is reachable by
/// design — if it stops working the configuration is broken and a passing invariant would be
/// meaningless. <see cref="Detonate"/> and <see cref="Sensitive"/> are denied by the engine's
/// member filter; reaching either one is the finding.
/// </summary>
public sealed class Canary
{
    /// <summary>
    /// Member names the engine's filter must reject. Includes the property getter's compiler-
    /// generated name, because a member filter sees MethodInfo for property accessors.
    /// </summary>
    public static readonly IReadOnlySet<string> DeniedMemberNames =
        new HashSet<string>(StringComparer.Ordinal) { "Detonate", "Sensitive", "get_Sensitive" };

    /// <summary>
    /// Static because the harness is single-threaded within a process and each AFL instance is
    /// its own process. Reset() must be called before every execution.
    /// </summary>
    public static bool Tripped { get; private set; }

    public static string? Reached { get; private set; }

    public static void Reset()
    {
        Tripped = false;
        Reached = null;
    }

    public string Allowed => "ok";

    public void Detonate()
    {
        Tripped = true;
        Reached ??= "Detonate()";
    }

    public string Sensitive
    {
        get
        {
            Tripped = true;
            Reached ??= "Sensitive";
            return "secret";
        }
    }
}
