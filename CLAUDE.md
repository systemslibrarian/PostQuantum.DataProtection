# CLAUDE.md

Project conventions for `PostQuantum.DataProtection`. Read this before making changes.

## What this project is

A small, focused library that **adds post-quantum / hybrid key wrapping to ASP.NET Core Data
Protection.** It plugs in as an `IXmlEncryptor` / `IXmlDecryptor` pair so that the keys ASP.NET Core
Data Protection persists on disk are encrypted with **ML-KEM-768 (FIPS 203) + AES-256-GCM** in a
hybrid envelope, with the classical layer reusing the **`PostQuantum.KeyManagement`** envelope
(`IContentKeyProvider`, AES-256-GCM under an Argon2id KEK).

This means cookie keys, antiforgery keys, and any `IDataProtector`-protected payload at rest are
protected by both a post-quantum KEM **and** a classical symmetric wrap — break either layer and
confidentiality holds.

## Layout

```
src/PostQuantum.DataProtection/                  # the library (multi-targets net8.0;net9.0;net10.0)
  PostQuantumXmlEncryptor.cs                     # IXmlEncryptor
  PostQuantumXmlDecryptor.cs                     # IXmlDecryptor
  Hybrid/
    HybridKemEnvelope.cs                         # versioned binary on-wire format + Encode/Decode
    HybridKemMode.cs                             # MlKemOnly | Hybrid (default: Hybrid)
    HybridCombiner.cs                            # HKDF(ml_kem_ss || classical_ss) -> AES-256 key
    MlKem.cs                                     # thin BouncyCastle wrapper (FIPS 203)
  Keys/
    IPostQuantumKeyStore.cs                      # pluggable storage of the long-lived ML-KEM keypair
    FilePostQuantumKeyStore.cs                   # default file impl, SK wrapped via IContentKeyProvider
    PostQuantumKeyPair.cs                        # value type: (id, public key, wrapped secret key)
  Hosting/
    DataProtectionBuilderExtensions.cs           # ProtectKeysWithPostQuantum(...)
    PostQuantumDataProtectionOptions.cs
  Internal/PortableEncoding.cs                   # length-prefixed Base64Url helpers (mirrors KMgmt)
tests/PostQuantum.DataProtection.Tests/          # xUnit roundtrip + security tests
samples/AspNetCore.Sample/                       # cookies + antiforgery protected by PQ DataProtection
Directory.Build.props                            # repo-wide build settings
```

## Core design rules

- **One envelope format, one parser.** Every encrypted XML element carries a single binary blob
  produced by `HybridKemEnvelope.Encode` and parsed by `HybridKemEnvelope.Decode`. Do not invent
  per-mode XML schemas — the mode is a byte inside the envelope.
- **Hybrid by default.** The default is `HybridKemMode.XWingHybrid` — SHA3-256 over the ML-KEM
  ciphertext, ML-KEM shared secret, classical secret, and a domain label (it binds the ciphertext).
  `HybridKemMode.Hybrid` (HKDF-SHA-256 over the ML-KEM + classical shared secrets) remains fully
  supported. `MlKemOnly` exists for testing and for callers who explicitly opt out of the classical
  layer. The mode is recorded per envelope, so changing the default is non-breaking. See
  [`docs/crypto-spec.md`](docs/crypto-spec.md) for the exact constructions.
- **`IContentKeyProvider` is the only thing the classical layer talks to.** Reuse its DEK +
  rotation discipline; do not re-implement key wrapping in this repo.
- **The long-lived ML-KEM keypair is itself envelope-encrypted at rest.** The secret key is wrapped
  by an `IContentKeyProvider` DEK before it touches disk. Loss of the host KEK ⇒ loss of the SK ⇒
  loss of the ability to decrypt persisted DP keys. This is by design and documented in
  [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
- **Hostile-input resistance.** `HybridKemEnvelope.Decode` caps every length-prefixed field and uses
  overflow-safe bounds arithmetic so malformed XML cannot trigger huge allocations.

## Engineering standards

- `Nullable`, `ImplicitUsings`, and **`TreatWarningsAsErrors`** are on repo-wide; analyzers run at
  `latest-recommended`. Keep the build at **zero warnings**. The only sanctioned suppression is
  `CA1707` in the *test* project (underscore test names).
- **Every public member is XML-documented.** `GenerateDocumentationFile` is on for the library.
- Builds are **deterministic** with **SourceLink** + symbol packages. Don't regress this.
- ML-KEM comes from **BouncyCastle.Cryptography** (FIPS 203). We do not implement PQ primitives
  ourselves.

## Tests

- xUnit, in `tests/`. Run with `dotnet test`.
- Tests use **`KekWorkFactor.LowMemory`** for speed — never copy those values into production guidance.
- New behavior needs a test. The load-bearing scenarios are: round-trip, tamper detection (envelope
  byte flip), wrong-KEK, mode mismatch, and the end-to-end ASP.NET Core Data Protection wiring.

## Documentation discipline

- Be honest. Anything the library cannot do yet goes in **KNOWN-GAPS.md** in plain language.
- README examples must compile against the real API. If you change a signature, update the README,
  `docs/`, and this file.
- Every top-level doc ends with: `*To God be the glory — 1 Corinthians 10:31.*`

## Versioning

- Currently `1.0.0` — first stable release. The public API and wire formats are **frozen**; SemVer
  applies. Depends on the stable `PostQuantum.KeyManagement 1.0.0`. Two items ship as documented
  limitations rather than blockers (see [`KNOWN-GAPS.md` §D](KNOWN-GAPS.md)): no third-party crypto
  audit yet, and the cloud stores are tested but not yet production-proven. Post-1.0, breaking
  changes are major-version bumps.
- Note breaking changes in `PackageReleaseNotes`, `CHANGELOG.md`, and the README status section.
- The envelope and keypair binary layouts are **frozen at version 1 for 1.0**
  (`HybridKemEnvelope.CurrentFormatVersion`). If you must change either post-1.0, bump that version,
  keep `Decode` able to read prior versions when feasible, reject unknown versions, and update
  [`docs/crypto-spec.md`](docs/crypto-spec.md) and [`docs/wire-format.md`](docs/wire-format.md).
