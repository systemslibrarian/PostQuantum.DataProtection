# PostQuantum.DataProtection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4.svg)](#requirements)
[![Status](https://img.shields.io/badge/status-preview-orange.svg)](#project-status)
[![NuGet](https://img.shields.io/badge/NuGet-PostQuantum.DataProtection-004880.svg)](https://www.nuget.org/packages/PostQuantum.DataProtection)
[![ci](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.DataProtection/actions/workflows/codeql.yml)

> **Post-quantum / hybrid key wrapping for ASP.NET Core Data Protection.**
> One line in `Program.cs` and every persisted Data Protection key — cookie keys, antiforgery keys,
> session tickets, anti-CSRF tokens, every `IDataProtector` payload at rest — is wrapped under an
> **ML-KEM-768 (FIPS 203) + AES-256-GCM** hybrid envelope.

`PostQuantum.DataProtection` plugs in as an `IXmlEncryptor` / `IXmlDecryptor` pair on the
`IDataProtectionBuilder` you already configure. The post-quantum layer is **ML-KEM-768** from
[BouncyCastle](https://www.bouncycastle.org/) (FIPS 203). The classical layer reuses
[`PostQuantum.KeyManagement`](https://www.nuget.org/packages/PostQuantum.KeyManagement) — the same
Argon2id-derived KEK + AES-256-GCM envelope already in the `PostQuantum.*` family — so the
long-lived PQ secret key is itself envelope-encrypted at rest by the host KEK.

It is the natural companion to [`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement)
and the rest of the `PostQuantum.*` family.

> ⚠️ **Preview (`0.1.0-preview.1`).** The API surface is small and the envelope wire-format is
> versioned, but both may still change before `1.0`. Read [KNOWN-GAPS.md](KNOWN-GAPS.md) before
> relying on it — it is deliberately blunt about what this library does and does **not** yet do.
> The threat model is in [`docs/threat-model.md`](docs/threat-model.md). No third-party audit yet —
> the engagement plan is in [`future.md`](future.md).

---

## When to use this

| Situation                                                                            | Verdict          |
| ------------------------------------------------------------------------------------ | ---------------- |
| You run ASP.NET Core and persist Data Protection keys (cookies, antiforgery, etc.).  | ✅ Yes           |
| Your threat model includes "harvest-now-decrypt-later" against the key store.        | ✅ Especially.   |
| You already use `PostQuantum.KeyManagement` to manage a host KEK.                    | ✅ Drop-in.      |
| You want defense-in-depth: a classical-broken passphrase ≠ lost confidentiality.     | ✅ Hybrid mode.  |
| You need a FIPS-validated implementation today (FIPS 140-3 module).                  | ❌ Not yet — see [KNOWN-GAPS.md §3](KNOWN-GAPS.md#3-not-fips-140-validated). |
| Your sole goal is rate-limiting key disclosure inside a single process.              | ❌ Use the BCL.  |
| You expect the public PQ key to leave the host (cross-party exchange).               | ❌ Out of scope — this is for at-rest wrapping. |

The honest one-liner: **this is at-rest defense-in-depth for Data Protection keys.** It does not
turn ASP.NET Core's request pipeline post-quantum; it makes sure the *keys that protect that
pipeline's tokens* stay confidential if the on-disk key store is ever stolen.

## Why hybrid (and why ML-KEM-768)

- **Hybrid = belt-and-braces.** The AES-256-GCM key that wraps each Data Protection element is
  HKDF-derived from *both* the ML-KEM shared secret *and* a classical secret minted by your
  `IContentKeyProvider`. An attacker has to defeat **both** layers to recover plaintext. A
  classically-broken passphrase still has ML-KEM in the way; a (hypothetical) quantum-broken
  ML-KEM still has the classical wrap in the way. This is the IETF hybrid-KEM pattern.
- **ML-KEM-768 is the general-purpose pick.** NIST category 3 (≈ 192-bit classical strength) — the
  same security level NIST recommends for general-purpose use. ML-KEM-512 sacrifices margin to
  save 384 bytes per encapsulation; ML-KEM-1024 raises margin at the cost of an extra 736 bytes.
  768 sits where most production traffic should sit.

The cipher choices are not configurable in `0.1`. That is on purpose — fewer knobs, fewer ways to
shoot yourself. ML-KEM-512 / 1024 selection is on the roadmap (see [`future.md`](future.md)).

## Try the demo in 60 seconds

A working sample ships in [`samples/AspNetCore.Sample`](samples/AspNetCore.Sample) — a minimal-API
host that issues cookies and antiforgery tokens whose underlying Data Protection keys are wrapped
with ML-KEM-768 + AES-256-GCM:

```bash
cd samples/AspNetCore.Sample
ASPNETCORE_ENVIRONMENT=Development dotnet run
# open the printed URL, hit /, watch the cookie roundtrip succeed, and inspect
# data-protection/ on disk to see the pqEnvelope element.
```

## Requirements

- .NET **8.0**, **9.0**, or **10.0** (multi-targeted, deterministic, SourceLink, symbol packages).
- A registered `PostQuantum.KeyManagement` `IContentKeyProvider` (one line of DI; see below).

## Installation

```bash
dotnet add package PostQuantum.DataProtection --prerelease
```

This package is dependency-light: ASP.NET Core Data Protection's abstractions,
`PostQuantum.KeyManagement` for the classical KEK, and BouncyCastle for ML-KEM-768. It pulls in no
HTTP clients, no logging adapters, no JSON. Cloud-backed PQ key stores (Azure Key Vault, AWS KMS,
GCP KMS) will ship as separate packages so the core stays small (see [`future.md`](future.md)).

## Quick start

```csharp
using Microsoft.AspNetCore.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// 1. Register PostQuantum.KeyManagement (provides IContentKeyProvider — the classical KEK).
builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("Missing passphrase");
    options.WorkFactor = KekWorkFactor.Interactive;
    options.KeyringPath = "keys/keyring.bin";
});

// 2. Wire post-quantum Data Protection. One line.
builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys/data-protection"))
    .ProtectKeysWithPostQuantum(options =>
    {
        options.KeyStorePath = "keys/pq-keystore.txt";
        options.Mode = HybridKemMode.Hybrid;  // default; production-safe
    });

WebApplication app = builder.Build();
```

That is the whole integration. On first run, the library generates an ML-KEM-768 keypair, wraps
its secret key under the `IContentKeyProvider` host KEK, and writes the pair to
`keys/pq-keystore.txt`. From that point on every Data Protection key persisted under
`keys/data-protection/` is wrapped in a `pqEnvelope` element.

## What lands on disk

`keys/data-protection/key-{guid}.xml` (the file ASP.NET Core Data Protection writes by itself)
now contains a single `<pqEnvelope>` element:

```xml
<?xml version="1.0" encoding="utf-8"?>
<key id="..." version="1">
  <creationDate>...</creationDate>
  <activationDate>...</activationDate>
  <expirationDate>...</expirationDate>
  <descriptor deserializerType="...">
    <descriptor>
      <encryption algorithm="AES_256_CBC" />
      <validation algorithm="HMACSHA256" />
      <encryptedSecret decryptorType="PostQuantum.DataProtection.PostQuantumXmlDecryptor, PostQuantum.DataProtection">
        <pqEnvelope xmlns="https://schemas.systemslibrarian.dev/pq-dataprotection/2026/01"
                    version="1" mode="Hybrid" publicKeyId="pq-mlkem768-...">
          BASE64URL...
        </pqEnvelope>
      </encryptedSecret>
    </descriptor>
  </descriptor>
</key>
```

The Base64Url blob holds the versioned binary envelope: `[FormatVersion | Mode | KemAlgorithm |
PublicKeyId | KemCiphertext | ClassicalWrappedKey | Nonce | Tag | Ciphertext]`. Every field is
length-prefixed and the decoder caps each length so a malformed XML element cannot trigger huge
allocations. The full wire-format is documented in [`docs/wire-format.md`](docs/wire-format.md).

`keys/pq-keystore.txt` holds the long-lived ML-KEM keypair:

```
active pq-mlkem768-a3c7e2b9
pair   <base64url token: public key + wrapped secret key>
```

The secret key is **always** wrapped by the host `IContentKeyProvider` before it touches disk —
even a host-FS read of the keystore yields ciphertext.

## Threat model and what we defend against

The full statement is in [`docs/threat-model.md`](docs/threat-model.md); the headline:

- ✅ **An attacker who exfiltrates the Data Protection key directory** sees a `pqEnvelope` and has
  to defeat both ML-KEM-768 **and** the classical KEK to recover the underlying DP key.
- ✅ **An attacker who exfiltrates the PQ keystore file** sees ML-KEM public keys in the clear
  (non-secret) and a secret key wrapped by AES-256-GCM under a key derived via Argon2id from a
  passphrase they do not have.
- ✅ **An attacker who tampers with a `pqEnvelope`** is detected by AES-256-GCM's authentication
  tag — never a silent plaintext on output.
- ✅ **An attacker today who plans to break the classical wrap with a future CRQC** ("harvest now,
  decrypt later") is blocked by ML-KEM on the same envelope.
- ❌ **An attacker who reads process memory of the running host** sees keys in use at that moment.
  No library can save you from that; mitigate at the host level.
- ❌ **An attacker who has both the keystore and the host passphrase** has won; the chain ends at
  the classical KEK.
- ❌ **A FIPS 140-validated cryptographic boundary.** BouncyCastle is not a FIPS module here. See
  [KNOWN-GAPS.md §3](KNOWN-GAPS.md#3-not-fips-140-validated).

## Honest limitations

- **No FIPS 140 validation today.** BouncyCastle ships a separate FIPS module; this library uses
  the standard build. See [KNOWN-GAPS.md §3](KNOWN-GAPS.md#3-not-fips-140-validated).
- **No third-party audit yet.** Written with care, automated tests, hostile-input tests, and a
  published threat model — but no external review. Tracked in [`future.md`](future.md).
- **Single active PQ keypair at a time.** Old PQ keypairs stay in the store so previously-wrapped
  Data Protection keys still decrypt after a PQ rotation; the active one is what fresh wraps
  target. This matches how ASP.NET Core Data Protection itself rotates DP keys.
- **No cloud-backed PQ key stores in `0.1`.** The pluggable `IPostQuantumKeyStore` exists; only
  the file-backed implementation ships today. Azure Key Vault, AWS KMS, GCP KMS are roadmap.
- **ML-KEM-768 only.** ML-KEM-512 and ML-KEM-1024 are not configurable yet.
- **Sync-over-async at the IXmlEncryptor seam.** ASP.NET Core's `IXmlEncryptor` contract is
  synchronous; the post-quantum operations are awaited via `.AsTask().GetAwaiter().GetResult()`
  inside the encryptor. This is the same pattern Data Protection itself uses for its built-in
  encryptors and is on the startup path, not the request path. See
  [KNOWN-GAPS.md §6](KNOWN-GAPS.md#6-sync-over-async-at-the-ixmlencryptor-seam).

See [KNOWN-GAPS.md](KNOWN-GAPS.md) for the full list.

## Supply chain verification

Every package this repo ships does the following — verify any of them before shipping:

- **Deterministic build.** `Deterministic=true` and (under CI)
  `ContinuousIntegrationBuild=true`. Re-running `dotnet pack` on the same commit produces
  byte-identical `.nupkg` / `.snupkg` outputs.
- **SourceLink + symbol package.** `IncludeSymbols=true`, `SymbolPackageFormat=snupkg`. The
  `.snupkg` carries debug info, and `Microsoft.SourceLink.GitHub` embeds the exact GitHub source
  URL for every PDB entry so debuggers fetch the right source for the right commit.
- **Embedded untracked sources.** `EmbedUntrackedSources=true` ensures generated files that are
  not under source control still ship in the symbol package.
- **Package validation.** `EnablePackageValidation=true` runs the .NET Package Validation analyser
  on every `dotnet pack` and fails the build on API surface drift between framework targets.
- **Verifiable dependencies.** `BouncyCastle.Cryptography` (a long-standing, audited PQC source),
  `PostQuantum.KeyManagement` (the sibling package — written by the same author, same standards),
  and the official `Microsoft.AspNetCore.DataProtection.*` packages. No private dependencies.
  Pin the patched `System.Security.Cryptography.Xml` 8.0.3 to avoid a known transitive advisory.
- **SBOM friendly.** All `<PackageReference>`s are explicit and versioned in the `.csproj`,
  which is what every SBOM generator (CycloneDX, SPDX, `dotnet-CycloneDX`,
  `Microsoft.Sbom.DotNetTool`) needs. The repo ships an SBOM-generation recipe in
  [`docs/supply-chain.md`](docs/supply-chain.md).

To verify a published package:

```bash
# 1. Download .nupkg and .snupkg from nuget.org.
# 2. Confirm SourceLink works — the .snupkg should embed GitHub URLs for every source file.
dotnet tool install --global sourcelink
sourcelink test PostQuantum.DataProtection.0.1.0-preview.1.nupkg

# 3. Reproduce the build from the matching commit.
git clone https://github.com/systemslibrarian/PostQuantum.DataProtection
cd PostQuantum.DataProtection
git checkout v0.1.0-preview.1
dotnet pack -c Release
diff <(sha256sum artifacts/PostQuantum.DataProtection.0.1.0-preview.1.nupkg) <(sha256sum from-nuget/PostQuantum.DataProtection.0.1.0-preview.1.nupkg)
```

## Building from source

```bash
dotnet build      # builds net8.0, net9.0, net10.0
dotnet test       # roundtrip, tamper, key-store, envelope decoder, ASP.NET Core integration
dotnet pack -c Release
```

## Project status

`0.1.0-preview.1` — first public preview. API and envelope wire-format may still change before
`1.0`; breaking changes are called out in `PackageReleaseNotes`, `CHANGELOG.md`, and this section.
The path to `1.0`, cloud-backed key stores, FIPS validation considerations, and external review
is mapped out in [`future.md`](future.md).

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
