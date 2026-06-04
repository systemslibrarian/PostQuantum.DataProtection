# PostQuantum.DataProtection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4.svg)](#requirements)
[![NuGet](https://img.shields.io/badge/NuGet-PostQuantum.DataProtection-004880.svg)](https://www.nuget.org/packages/PostQuantum.DataProtection)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM--768-228B22.svg)](docs/threat-model.md)
[![ci](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/codeql.yml)

> **Post-quantum / hybrid key wrapping for ASP.NET Core Data Protection.**
> One line in `Program.cs` and every persisted Data Protection key — cookie keys, antiforgery
> keys, session tickets, Blazor circuit tokens, every `IDataProtector` payload at rest — is
> wrapped under an **ML-KEM-768 (FIPS 203) + AES-256-GCM hybrid envelope.**

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys"))
    .ProtectKeysWithPostQuantum(o => o.KeyStorePath = "keys/pq-keystore.txt");
```

That's it.

---

## What you get

Six packages, one CLI, four end-to-end samples. Mix and match.

| Package | Purpose |
|---|---|
| **`PostQuantum.DataProtection`** | The core. Encryptor / decryptor, key manager, file-backed key store, DI extensions, health check, scheduled rotation, retention/prune helper, metrics + tracing. Supports ML-KEM-512, ML-KEM-768, ML-KEM-1024 + HKDF and X-Wing combiners. |
| **`PostQuantum.DataProtection.AzureKeyVault`** | `IPostQuantumKeyStore` backed by Azure Key Vault Secrets. One line: `services.AddPostQuantumDataProtectionAzureKeyVault(vaultUri)`. |
| **`PostQuantum.DataProtection.Aws`** | `IPostQuantumKeyStore` backed by AWS Secrets Manager. One line: `services.AddPostQuantumDataProtectionAws()`. |
| **`PostQuantum.DataProtection.Redis`** | `IPostQuantumKeyStore` backed by Redis. Natural pair with `PersistKeysToStackExchangeRedis`. |
| **`PostQuantum.DataProtection.OpenTelemetry`** | One-line OTel wiring. `.AddPostQuantumDataProtectionInstrumentation()` on a `MeterProviderBuilder` / `TracerProviderBuilder`. |
| **`PostQuantum.DataProtection.Testing`** | `FakePostQuantumKeyStore` + `AddPostQuantumDataProtectionTesting()` for consumer unit tests — no cloud, no disk. |
| **`PostQuantum.DataProtection.Cli`** (`pq-dp`) | `dotnet tool` for inspecting persisted DP key XML files. No secrets emitted. |

Samples:

| Sample | What it shows |
|---|---|
| [`AspNetCore.Sample`](samples/AspNetCore.Sample) | Minimal-API host with cookie auth + antiforgery, both PQ-protected. |
| [`WorkerService.Sample`](samples/WorkerService.Sample) | Worker Service using PQ outside ASP.NET Core, with scheduled rotation. |
| [`Blazor.Sample`](samples/Blazor.Sample) | Blazor Server with PQ-protected circuit + cookie + `IDataProtector` roundtrip. |
| [`MultiReplica.Sample`](samples/MultiReplica.Sample) | Two simulated replicas sharing one Key Vault — proves the multi-replica shape end to end. |

---

## Why hybrid (and why ML-KEM-768)

- **Hybrid = belt-and-braces.** The AES-256-GCM key that wraps each Data Protection element is
  HKDF-derived from *both* the ML-KEM shared secret *and* a classical secret from your
  `IContentKeyProvider`. An attacker has to defeat **both** layers to recover plaintext. A
  classically-broken passphrase still has ML-KEM in the way; a (hypothetical) quantum-broken
  ML-KEM still has the classical wrap in the way. This is the IETF hybrid-KEM pattern.
- **ML-KEM-768 is the general-purpose pick.** NIST category 3 (≈ 192-bit classical strength) —
  the level NIST recommends for general use. We default there; switch to 512 or 1024 when the
  selectable parameter set lands (see [`KNOWN-GAPS.md` §C1](KNOWN-GAPS.md#c1-selectable-ml-kem-parameter-set)).
- **Verified against FIPS 203.** Our integration is pinned by a NIST-aligned KAT vector: given
  the seed bytes from `post-quantum-cryptography/KAT`, BouncyCastle's ML-KEM-768 produces the
  exact `pk` (1184 bytes), `sk` (2400 bytes), and decapsulates the published ciphertext to the
  published shared secret — byte for byte. The test runs on every PR.

## When to use this

| Situation | Verdict |
|---|---|
| You run ASP.NET Core, Blazor, or any .NET host with Data Protection. | ✅ Yes |
| Your threat model includes "harvest-now, decrypt-later" against the key store. | ✅ Especially |
| You want defense-in-depth without ripping out your existing Data Protection wiring. | ✅ One line |
| You need a FIPS 140-3 validated module today. | ❌ Roadmap — see [§C6](KNOWN-GAPS.md#c6-fips-140-3-path-via-the-bc-fips-module) |
| You want PQ session-key negotiation over the wire. | ❌ Different layer — TLS hybrid groups belong in the stack |

## Quick start

```bash
dotnet add package PostQuantum.DataProtection --prerelease
dotnet add package PostQuantum.KeyManagement --prerelease
```

```csharp
using Microsoft.AspNetCore.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("Missing passphrase");
    options.WorkFactor = KekWorkFactor.Moderate;
    options.KeyringPath = "keys/host-keyring.bin";
});

builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys/data-protection"))
    .ProtectKeysWithPostQuantum(options =>
    {
        options.KeyStorePath = "keys/pq-keystore.txt";
        options.Mode = HybridKemMode.Hybrid;
        options.RotationInterval = TimeSpan.FromDays(90);  // optional auto-rotation
    });

builder.Services.AddHealthChecks().AddPostQuantumDataProtection();
```

### Configure from `appsettings.json` instead of code

```jsonc
{
  "PostQuantumDataProtection": {
    "KeyStorePath": "keys/pq-keystore.txt",
    "Mode": "Hybrid",
    "RotationInterval": "90.00:00:00"
  }
}
```

```csharp
builder.Services
    .AddDataProtection()
    .ProtectKeysWithPostQuantum(builder.Configuration.GetSection("PostQuantumDataProtection"));
```

### Replace the file store with Azure Key Vault

```csharp
builder.Services.AddPostQuantumDataProtectionAzureKeyVault(new Uri("https://my-vault.vault.azure.net/"));
```

### Replace the file store with AWS Secrets Manager

```csharp
builder.Services.AddPostQuantumDataProtectionAws(o => o.Region = Amazon.RegionEndpoint.USEast1);
```

### Wire OpenTelemetry in one line

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddPostQuantumDataProtectionInstrumentation().AddPrometheusExporter())
    .WithTracing(t => t.AddPostQuantumDataProtectionInstrumentation().AddOtlpExporter());
```

### Unit-test consumer code without standing up a real chain

```csharp
[Fact]
public void My_service_protects_and_unprotects()
{
    var services = new ServiceCollection();
    services.AddPostQuantumDataProtectionTesting();
    using ServiceProvider sp = services.BuildServiceProvider();

    IDataProtector p = sp.GetRequiredService<IDataProtectionProvider>().CreateProtector("p");
    Assert.Equal("hi", p.Unprotect(p.Protect("hi")));
}
```

### Inspect a persisted key file from the CLI

```bash
dotnet tool install --global PostQuantum.DataProtection.Cli --prerelease
pq-dp inspect keys/data-protection/key-c6b3b03f-b73a-477b-92e5-d19ae0e0b5fd.xml
```

```text
Format version:      1
Mode:                Hybrid
KEM algorithm:       ML-KEM-768
Public key id:       pq-mlkem768-4411e03446f5
KEM ciphertext:      1088 bytes
Classical wrap:      236 chars
AES-GCM nonce:       12 bytes
AES-GCM tag:         16 bytes
AES-GCM ciphertext:  120 bytes
```

## What lands on disk

```xml
<encryptedSecret decryptorType="PostQuantum.DataProtection.PostQuantumXmlDecryptor, …">
  <pqEnvelope xmlns="https://schemas.systemslibrarian.dev/pq-dataprotection/2026/01"
              version="1" mode="Hybrid" publicKeyId="pq-mlkem768-…">
    BASE64URL…
  </pqEnvelope>
</encryptedSecret>
```

The Base64Url blob is a versioned binary envelope: `[FormatVersion | Mode | KemAlgorithm |
PublicKeyId | KemCiphertext | ClassicalWrappedKey | Nonce | Tag | Ciphertext]`. Every field is
length-prefixed and capped at 1 MiB. Full byte layout in [`docs/wire-format.md`](docs/wire-format.md).

## Performance

Real numbers from `BenchmarkDotNet` on a modern x86_64 host (full table in
[`docs/benchmarks.md`](docs/benchmarks.md)):

| Operation | Mean |
|---|---|
| ML-KEM-768 encapsulate | ~93 µs |
| ML-KEM-768 decapsulate | ~101 µs |
| Full envelope encrypt (Hybrid) | ~89 µs |
| Full envelope decrypt (Hybrid) | ~137 µs |

Envelope work happens at **DP key persist / load** — startup-path, not request-path. Cookie
verification, antiforgery validation, and `IDataProtector.Unprotect` all read keys from the
in-memory key ring; they never go through the envelope.

## Observability

The library publishes a `Meter` and an `ActivitySource` named `PostQuantum.DataProtection`.
Subscribe with OpenTelemetry (or any `IMeterListener`):

| Signal | What it tells you |
|---|---|
| `pq_dataprotection.encryptions` | Rate of fresh DP keys being wrapped. Tagged by `mode`. |
| `pq_dataprotection.decryptions` | Rate of envelope reads. Tagged by `mode`. |
| `pq_dataprotection.decrypt_failures` | Tagged by `reason`: `wrong_xml_element`, `malformed_envelope`, `unsupported_algorithm`, `unknown_keypair`, `auth_failed`. **Page on any non-zero rate.** |
| `pq_dataprotection.rotations` | Rate of PQ keypair rotations. Should be quiet outside scheduled windows. |
| `pq_dataprotection.encrypt.duration` / `decrypt.duration` | Histograms in ms. P95 should sit < 1 ms on modern hardware. |
| `AddPostQuantumDataProtection()` health check | Real roundtrip on every probe. **Page if Unhealthy.** |

## Threat model and security posture

[`docs/threat-model.md`](docs/threat-model.md) is the precise statement: attacker model (A1 → A6 vs.
B1 → B4) and 10 numbered security invariants the library is designed to hold. Each invariant
corresponds to one or more tests.

[`SECURITY.md`](SECURITY.md) covers reporting vulnerabilities (use GitHub Security Advisories,
not public issues), supported versions, and the recommended deployment posture.

[`docs/deployment.md`](docs/deployment.md) is the production operations checklist: pre-deploy
verification, multi-replica model, KEK rotation playbook, disaster recovery matrix, monitoring
signals.

## Honest scope of "post-quantum"

The library wraps Data Protection keys at rest with a verified-against-FIPS-203 ML-KEM-768 + AES-256-GCM
hybrid envelope. That is the entire claim. We do **not** claim to make ASP.NET Core's request
pipeline post-quantum, to negotiate PQ session keys, or to be FIPS 140-3 validated today. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the full breakdown of what's deliberate, what's roadmap, and
what's been closed across previews.

## Migrating from another `IXmlEncryptor`

Whether you're on `ProtectKeysWithDpapiNG`, `ProtectKeysWithAzureKeyVault` (the key wrap, not the
secrets store), or `ProtectKeysWithCertificate`, the migration is non-disruptive — existing keys
keep decrypting under their old decryptor type while fresh keys roll forward under PQ. Step by
step in [`docs/migration.md`](docs/migration.md).

## Supply chain

- **Deterministic** builds with **CI-enforced reproducibility** (the CI repacks twice and asserts
  byte-identical `.nupkg` SHA-256).
- **SourceLink + symbol packages** so debuggers fetch the exact GitHub source for every
  commit you ship.
- **`EnablePackageValidation`** catches API surface drift between framework targets.
- **`TreatWarningsAsErrors`** plus `latest-recommended` analyzers — zero-warning policy across
  the repo.
- **Pinned transitive overrides** for known-vulnerable packages (e.g. `System.Security.Cryptography.Xml`
  pinned to the patched 8.0.3 to avoid GHSA-37gx-xxp4-5rgx and GHSA-w3x6-4m5h-cxqf).
- **SBOM-friendly metadata.** Every dependency is an explicit `<PackageReference>`. Recipes for
  CycloneDX and the Microsoft SBOM tool in [`docs/supply-chain.md`](docs/supply-chain.md).

To verify a published package:

```bash
sourcelink test PostQuantum.DataProtection.<version>.nupkg
# Reproduce the build from the matching commit and compare SHA-256:
git checkout v<version>
dotnet pack -c Release -o /tmp/local
sha256sum /tmp/local/PostQuantum.DataProtection.<version>.nupkg
```

## Testing

```bash
dotnet build PostQuantum.DataProtection.slnx -c Release
dotnet test PostQuantum.DataProtection.slnx -c Release --no-build
```

**87 tests** across four suites — core, AzureKeyVault, Aws, Testing. Coverage gate at ≥ 85% line
/ ≥ 75% branch (current 89.5% line / 78.6% branch). Property-based fuzz-lite contract tests
drive 30 000 random inputs through both decoders on every run; a standalone SharpFuzz harness in
`fuzz/` is set up for AFL-driven exploration.

## Requirements

- .NET **8.0**, **9.0**, or **10.0** (multi-targeted).
- A registered `PostQuantum.KeyManagement` `IContentKeyProvider` for the classical KEK layer.

## Project status

`0.1.0-preview.4`. The API surface and the binary envelope wire format are versioned and
backward-compatible across the preview series (every envelope written by `preview.1` decodes
under `preview.4`). Pre-`1.0` the wire format may still change with a deliberate version bump
and a `CHANGELOG.md` note. The path to `1.0` is mapped in [`future.md`](future.md).

The two remaining gates on `1.0` are calendar-time, not code-time: third-party cryptographic
review, and at least one cloud-backed key store in real production use. Both are tracked in
[`KNOWN-GAPS.md` §D](KNOWN-GAPS.md#d-honest-gates-on-10).

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
