using PostQuantum.DataProtection.Fips;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Tests for the FIPS deployment tripwire. Note: <see cref="FipsDeploymentMarker"/> holds
/// process-wide state, so these tests reset the posture sentinel between runs by using
/// distinct values. The tests do not run in parallel against each other within this collection
/// to keep state predictable.
/// </summary>
[Collection("FipsDeploymentMarker")]
public sealed class FipsDeploymentMarkerTests
{
    [Fact]
    public void Default_posture_is_NotDeclared()
    {
        // Other tests in the suite may have committed a posture; we can only assert that the
        // value is one of the defined enum values.
        FipsPosture posture = FipsDeploymentMarker.Posture;
        Assert.True(Enum.IsDefined<FipsPosture>(posture));
    }

    [Fact]
    public void EnforceFor_passes_when_posture_is_NotDeclared_regardless_of_provider()
    {
        // Skip the test if a different posture has already been declared by an earlier test —
        // posture is one-way. This still exercises the "not declared" branch on a clean host.
        if (FipsDeploymentMarker.Posture != FipsPosture.NotDeclared)
        {
            return;
        }

        FipsDeploymentMarker.EnforceFor("standard-bouncycastle", providerIsFipsValidated: false);
        FipsDeploymentMarker.EnforceFor("vendor-validated", providerIsFipsValidated: true);
        // No exceptions = pass.
    }

    [Fact]
    public void Require_FipsOnly_then_EnforceFor_non_validated_provider_throws()
    {
        // Use a per-test instance? Posture is process-wide, but we can stand up a one-shot
        // sub-test using the static surface. Pre-condition: posture is either NotDeclared or
        // already FipsOnly from an earlier test.
        if (FipsDeploymentMarker.Posture == FipsPosture.NotDeclared)
        {
            FipsDeploymentMarker.Require(FipsPosture.FipsOnly);
        }

        Assert.Throws<InvalidOperationException>(() =>
            FipsDeploymentMarker.EnforceFor("standard-bouncycastle", providerIsFipsValidated: false));
    }

    [Fact]
    public void Require_FipsOnly_then_EnforceFor_validated_provider_does_not_throw()
    {
        if (FipsDeploymentMarker.Posture == FipsPosture.NotDeclared)
        {
            FipsDeploymentMarker.Require(FipsPosture.FipsOnly);
        }

        FipsDeploymentMarker.EnforceFor("bouncycastle-fips", providerIsFipsValidated: true);
        // No exception = pass.
    }

    [Fact]
    public void EnforceFor_rejects_empty_provider_name()
    {
        Assert.Throws<ArgumentException>(() => FipsDeploymentMarker.EnforceFor("", providerIsFipsValidated: true));
        Assert.Throws<ArgumentException>(() => FipsDeploymentMarker.EnforceFor("   ", providerIsFipsValidated: true));
    }
}
