namespace PostQuantum.DataProtection.Fips;

/// <summary>
/// Declarative marker for hosts that must run under FIPS 140-3 compliance.
/// </summary>
/// <remarks>
/// <para>
/// Calling <see cref="Require"/> at host startup commits the process to a FIPS-only posture
/// — runtime checks will fail fast if the active cryptographic chain doesn't satisfy the
/// declared requirements. The marker doesn't provide cryptography itself; it's a tripwire to
/// catch misconfiguration before envelopes are written under a non-FIPS provider.
/// </para>
/// <para>
/// <b>What this package does NOT do.</b> It does not embed a FIPS-validated ML-KEM
/// implementation. The actual validated provider must come from somewhere else — see the
/// README for the supported integration paths.
/// </para>
/// </remarks>
public static class FipsDeploymentMarker
{
    private static volatile FipsPosture _posture = FipsPosture.NotDeclared;

    /// <summary>The currently declared FIPS posture for this process.</summary>
    public static FipsPosture Posture => _posture;

    /// <summary>
    /// Commits this process to the given FIPS posture. Cannot be downgraded once set.
    /// </summary>
    /// <param name="posture">The required posture.</param>
    /// <exception cref="InvalidOperationException">
    /// A different posture is already declared. Posture is a one-way commitment.
    /// </exception>
    public static void Require(FipsPosture posture)
    {
        FipsPosture current = _posture;
        if (current == posture)
        {
            return;
        }

        if (current != FipsPosture.NotDeclared && current != posture)
        {
            throw new InvalidOperationException(
                $"FIPS posture has already been declared as '{current}'. Cannot redeclare as '{posture}'.");
        }

        _posture = posture;
    }

    /// <summary>
    /// Throws if the active ML-KEM provider does not satisfy the declared <see cref="Posture"/>.
    /// Wire this into your host's readiness probe and into the
    /// <see cref="Microsoft.Extensions.Hosting.IHostedService"/> startup path so a non-FIPS
    /// provider cannot accidentally write envelopes to disk.
    /// </summary>
    /// <param name="activeProviderName">
    /// A human-readable identifier of the active provider (e.g. <c>"System.Security.Cryptography.MLKem (BCL)"</c>
    /// or <c>"BouncyCastle.Cryptography 2.6.x"</c> or <c>"BouncyCastle FIPS 2.x"</c>).
    /// </param>
    /// <param name="providerIsFipsValidated">
    /// Whether the active provider has been declared FIPS 140-3 validated by its vendor. The
    /// consumer is responsible for this attestation — this method only enforces consistency,
    /// not the validation itself.
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// <see cref="Posture"/> is <see cref="FipsPosture.FipsOnly"/> but the active provider is
    /// not FIPS-validated.
    /// </exception>
    public static void EnforceFor(string activeProviderName, bool providerIsFipsValidated)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(activeProviderName);

        if (_posture == FipsPosture.FipsOnly && !providerIsFipsValidated)
        {
            throw new InvalidOperationException(
                $"FIPS posture is FipsOnly but the active ML-KEM provider '{activeProviderName}' is not declared FIPS 140-3 validated. " +
                "Either switch to a validated provider (e.g. BouncyCastle FIPS) or downgrade the declared posture. " +
                "See the PostQuantum.DataProtection.Fips README for the integration paths.");
        }
    }
}

/// <summary>The declared FIPS 140-3 posture for the host process.</summary>
public enum FipsPosture
{
    /// <summary>No posture declared. The default. Process accepts any provider.</summary>
    NotDeclared = 0,

    /// <summary>Process declares it must run only against a FIPS 140-3 validated cryptographic chain.</summary>
    FipsOnly = 1,
}
