# PostQuantum.DataProtection.Fips

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

Deployment guidance + declarative tripwire for running `PostQuantum.DataProtection` under
FIPS 140-3 compliance regimes.

> **Stable (`1.0.1`).**

## What this package is

A **tripwire**, not a cryptographic implementation. The package ships:

- `FipsDeploymentMarker.Require(FipsPosture.FipsOnly)` — call at startup to commit the process
  to a FIPS-only posture.
- `FipsDeploymentMarker.EnforceFor(providerName, providerIsFipsValidated)` — call from your
  health check or readiness probe to fail fast if the active provider doesn't satisfy the
  declared posture.

## What this package is NOT

It is **not** a FIPS-validated ML-KEM implementation. We do not embed one for two reasons:

1. The validated implementations (BouncyCastle FIPS, vendor HSM SDKs) are distributed under
   their own licenses, often paid, and are operator-controlled.
2. Validation status is *attested* by the vendor and tied to a specific binary build. Embedding
   a non-current build of someone else's FIPS module would silently invalidate the validation.

You bring the validated provider; this package helps you not deploy without one.

## Integration paths

### Path A — BouncyCastle FIPS (most common today)

[BouncyCastle.NET FIPS](https://www.bouncycastle.org/fips_net.html) is a separately-distributed,
FIPS 140-3 validated build of BouncyCastle. It is **not** the same artifact as
`BouncyCastle.Cryptography` on NuGet.

Acquisition + license:
- Visit the BouncyCastle FIPS download page.
- Read the licensing terms; commercial use typically requires a paid agreement.
- Download the validated binary that matches your target framework.

Integration:

```csharp
// 1. Replace the standard BouncyCastle.Cryptography reference in your host project
//    with the BouncyCastle FIPS assembly (you'll add a direct DLL reference, not a
//    NuGet PackageReference, in most cases).
// 2. Declare the posture before any encryption.

using PostQuantum.DataProtection.Fips;

FipsDeploymentMarker.Require(FipsPosture.FipsOnly);

// 3. After registering PostQuantum.DataProtection but before the first encryption,
//    enforce against the active provider name.

FipsDeploymentMarker.EnforceFor(
    activeProviderName: "BouncyCastle FIPS 2.x",
    providerIsFipsValidated: true);
```

The simplest place to call `EnforceFor` is from a custom `IHostedService` that runs at
`ApplicationStarted` and from `AddPostQuantumDataProtection()` health check.

### Path B — Validated HSM SDK

Some HSM vendors ship validated client SDKs that expose ML-KEM via PKCS#11 or a vendor
API. To use them:

1. Implement a custom `IPostQuantumKeyStore` that talks to the HSM (see
   [`src/PostQuantum.DataProtection.AzureKeyVault`](../PostQuantum.DataProtection.AzureKeyVault)
   for the reference shape).
2. Implement the ML-KEM operations against the HSM's API.
3. Declare and enforce posture as in Path A.

This package can't help with steps 1–2 — that's vendor-specific work — but the posture
enforcement (step 3) is identical regardless of where the validated chain lives.

### Path C — .NET FIPS-validated provider (when available)

Microsoft is working toward FIPS validation for the .NET BCL cryptographic providers. When
that arrives, ML-KEM on `net10.0+` will run against the validated build with no consumer
configuration changes. This package's `EnforceFor("System.Security.Cryptography.MLKem (BCL, FIPS-validated)", true)`
will be the right call.

Status: track [`PostQuantum.DataProtection/future.md`](../../future.md) for updates.

## Recommended use

```csharp
using PostQuantum.DataProtection.Fips;

builder.Services.AddPostQuantumKeyManagement(...);
builder.Services.AddDataProtection().ProtectKeysWithPostQuantum(...);

// 1. Commit the posture before the host runs.
FipsDeploymentMarker.Require(FipsPosture.FipsOnly);

// 2. Wire it into the health check so liveness fails fast if the active provider drifts.
builder.Services.AddHealthChecks().AddCheck("fips-posture", () =>
{
    try
    {
        FipsDeploymentMarker.EnforceFor(
            activeProviderName: GetMyActiveProviderName(),
            providerIsFipsValidated: IsMyActiveProviderFipsValidated());
        return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy();
    }
    catch (InvalidOperationException ex)
    {
        return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy(ex.Message);
    }
});
```

## Limitations

- **The tripwire is only as honest as your attestation.** Passing
  `providerIsFipsValidated: true` for a non-validated provider defeats the check. The
  enforcement is meant to catch *accidental* drift, not malicious misconfiguration.
- **Posture is process-wide.** You cannot have one part of the host running FIPS-only and
  another running not.
- **Posture is one-way.** Once declared, it cannot be downgraded — only the process restart
  resets it. This is deliberate: a downgrade would silently turn off the very check the
  posture exists to enforce.

---

*To God be the glory — 1 Corinthians 10:31.*
