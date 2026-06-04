# Changelog

All notable changes to `PostQuantum.DataProtection` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the explicit caveat that the
binary wire format may change in breaking ways across `0.x` minor versions. See
[`KNOWN-GAPS.md` §9](KNOWN-GAPS.md#9-wire-format-is-versioned-but-pre-10).

## [Unreleased]

## [0.1.0-preview.1] — 2026-06-03

First public preview. The release notes are intentionally complete; later releases will reference
this commit as the baseline.

### Added

- `IXmlEncryptor` / `IXmlDecryptor` pair (`PostQuantumXmlEncryptor`,
  `PostQuantumXmlDecryptor`) that wraps every persisted ASP.NET Core Data Protection key in an
  ML-KEM-768 (FIPS 203) + AES-256-GCM hybrid envelope.
- `ProtectKeysWithPostQuantum()` extension on `IDataProtectionBuilder` — one line in
  `Program.cs` to enable post-quantum key wrapping on a host that already registers
  `IContentKeyProvider` via `AddPostQuantumKeyManagement(...)`.
- `HybridKemMode { MlKemOnly, Hybrid }` (default `Hybrid`) with HKDF-SHA-256-based key derivation
  and explicit domain-separation labels per mode.
- `IPostQuantumKeyStore` extension point with `FilePostQuantumKeyStore` reference implementation —
  atomic temp-file + `File.Replace` writes with bounded retry on Windows-specific `IOException`.
- `PostQuantumKeyManager` — generates the inaugural ML-KEM-768 keypair on first run, wraps its
  secret key under `IContentKeyProvider`, persists via the store, and serves
  encapsulate/decapsulate calls by id.
- Versioned binary wire format for the envelope and the keypair token, with hostile-input
  decoders that cap every length-prefixed field at 1 MiB and use overflow-safe bounds arithmetic.
- `TryDecode` overloads on every public token decoder for untrusted-input call sites.
- Safe `ToString()` on every record that carries byte arrays — never leaks ciphertext or
  classical wrapped-key tokens to logs.
- Multi-targets `net8.0`, `net9.0`, `net10.0` with `Deterministic=true`,
  `ContinuousIntegrationBuild=true` (under GitHub Actions), `SourceLink + snupkg`,
  `EnablePackageValidation=true`, `EmbedUntrackedSources=true`, `TreatWarningsAsErrors=true`,
  `AnalysisLevel=latest-recommended`.
- Docs: `README.md`, `SECURITY.md`, `KNOWN-GAPS.md`, `docs/threat-model.md`,
  `docs/wire-format.md`, `docs/supply-chain.md`, `future.md`.
- Working ASP.NET Core sample at `samples/AspNetCore.Sample` showing cookies + antiforgery
  protected by the PQ encryptor.

### Security

- Pinned `System.Security.Cryptography.Xml` 8.0.3 explicitly to side-step
  [GHSA-37gx-xxp4-5rgx](https://github.com/advisories/GHSA-37gx-xxp4-5rgx) and
  [GHSA-w3x6-4m5h-cxqf](https://github.com/advisories/GHSA-w3x6-4m5h-cxqf) in the unpatched 8.0.x
  transitive line.
- All plaintext key material (ML-KEM shared secrets, classical DEK bytes, derived AES keys,
  ML-KEM secret keys) is zeroed via `CryptographicOperations.ZeroMemory` as soon as it is no
  longer needed.

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.DataProtection/compare/v0.1.0-preview.1...HEAD
[0.1.0-preview.1]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.1
