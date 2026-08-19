using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> that skips the test (with a stated reason) when the host
/// runtime lacks the native ML-KEM primitive. macOS has no .NET 10 ML-KEM backend, so every
/// test that performs a real encapsulation would otherwise fail with
/// <see cref="PlatformNotSupportedException"/> rather than skip.
/// <para>
/// Mirrors the discipline used across these repositories: a test that cannot run its crypto
/// skips with a reason, never silently passes. The Linux leg still runs the full suite, so a
/// genuine regression cannot hide behind these skips.
/// </para>
/// </summary>
public sealed class PqcFactAttribute : FactAttribute
{
    public PqcFactAttribute()
    {
        if (!MLKem.IsSupported)
        {
            Skip = PqcSupport.SkipReason;
        }
    }
}

/// <summary>
/// The <see cref="TheoryAttribute"/> counterpart to <see cref="PqcFactAttribute"/>.
/// </summary>
public sealed class PqcTheoryAttribute : TheoryAttribute
{
    public PqcTheoryAttribute()
    {
        if (!MLKem.IsSupported)
        {
            Skip = PqcSupport.SkipReason;
        }
    }
}

internal static class PqcSupport
{
    internal const string SkipReason =
        "ML-KEM not supported on this host (needs .NET 10 BCL on OpenSSL 3.5+ or recent Windows).";
}
