# Changelog

All notable changes to `PostQuantum.DataProtection` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the explicit caveat that the
binary wire format may change in breaking ways across `0.x` minor versions. See
[`KNOWN-GAPS.md` §9](KNOWN-GAPS.md#9-wire-format-is-versioned-but-pre-10).

## [Unreleased]

## [0.1.0-preview.3] — 2026-06-04

Production-readiness pass. Closes 9 of the 11 items from the "what would push this to 10/10
production-ready" list. **Backward-compatible** — every envelope and keystore file from
`preview.1` / `preview.2` still decodes byte-for-byte. **No crypto-logic changes.**

### Added

- **NIST ACVP / FIPS 203 KAT** (`AcvpKatTests`): pins BouncyCastle's ML-KEM-768 against a real
  NIST-aligned vector from
  [`post-quantum-cryptography/KAT`](https://github.com/post-quantum-cryptography/KAT) —
  `d || z` seed → expected pk (1184 B), expected sk (2400 B), decapsulate the NIST ct →
  expected ss (32 B). Standard-conformance verification, not "self-consistent" verification.
- **`System.Diagnostics.Metrics` integration** — `Meter("PostQuantum.DataProtection")` with
  counters (`encryptions`, `decryptions`, `decrypt_failures`, `rotations`), duration
  histograms, and an `ActivitySource` for distributed tracing. Subscribe via OpenTelemetry's
  `AddMeter` / `AddSource`.
- **Concurrency stress tests** — 16-thread `Parallel.ForEachAsync` exercising the encryptor,
  decryptor, and `RotateAsync` together; a "first-run race" test proving N concurrent first-
  callers see exactly one inaugural keypair. The documented thread-safety claim is now a
  tested claim.
- **Code-coverage measurement** — coverlet collector with a CI gate at **≥ 85% line / ≥ 75%
  branch**. Current coverage: **89.5% line / 78.6% branch**.
- **Reproducible-build verification** in CI — repacks twice and asserts byte-identical SHA-256
  on the two `.nupkg` outputs. A regression here means supply-chain integrity has slipped.
- **AOT / trimming audit** (`docs/aot.md`) — not AOT-compatible today because BouncyCastle 2.6.x
  uses runtime reflection. Documented honestly; `IsTrimmable=false` set explicitly.
- **BenchmarkDotNet harness** in `benchmarks/` with real numbers in `docs/benchmarks.md`:
  ML-KEM-768 keygen ~75 µs, encap ~93 µs, decap ~101 µs; full envelope encrypt ~89 µs, decrypt
  ~137 µs on the reference host.
- **Production deployment guide** (`docs/deployment.md`) — pre-deploy checklist, multi-replica
  model, KEK rotation playbook, disaster-recovery matrix, monitoring signal list.
- **Property-based "fuzz-lite" tests** (`HostileInputContractTests`) — 30 000 randomly-generated
  byte arrays driven through `HybridKemEnvelope.Decode` and `PostQuantumKeyPair.Decode` on
  every CI run, asserting the documented exception-type contract.
- **SharpFuzz harness** in `fuzz/PostQuantum.DataProtection.Fuzz` for AFL-driven exploration of
  the same decoders.

### Companion package: `PostQuantum.DataProtection.AzureKeyVault 0.1.0-preview.3`

- New package: Azure Key Vault-backed `IPostQuantumKeyStore`. Stores each ML-KEM-768 keypair as
  a Key Vault Secret, plus a small "active" pointer secret. One-line wiring:
  `services.AddPostQuantumDataProtectionAzureKeyVault(vaultUri)`. Uses
  `DefaultAzureCredential` by default; supports any `TokenCredential`. Concurrent-safe;
  active-pointer write is ordered after the keypair-secret write so a crash leaves an
  "orphan keypair" rather than a "ghost active pointer."
- Unit-tested via a narrow `IKeyVaultSecretClient` seam with an in-memory fake — 6 tests
  passing, no Azure account required.

### Tests

- **78 xUnit tests passing** in the core suite (was 63 in `preview.2`):
  - 3 new NIST ACVP KATs.
  - 3 new concurrency stress tests.
  - 3 new telemetry/metrics emission tests.
  - 2 new keypair-observability tests (covering `ListKeysAsync`).
  - 2 new health-check tests.
  - 3 new property-based fuzz-lite contract tests (30 000 iterations each).
- **6 xUnit tests passing** in the new `PostQuantum.DataProtection.AzureKeyVault.Tests` suite.

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.DataProtection/compare/v0.1.0-preview.3...HEAD
[0.1.0-preview.3]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.3

## [0.1.0-preview.2] — 2026-06-04

Hardening + observability pass on top of `0.1.0-preview.1`. **Backward-compatible** — every
envelope and keystore file written by `preview.1` still decodes byte-for-byte. No crypto-logic
changes (ML-KEM-768 encapsulation, HKDF-SHA-256 derivation, AES-256-GCM are byte-for-byte
identical).

### Added

- `AddPostQuantumDataProtection()` on `IHealthChecksBuilder` and
  `PostQuantumDataProtectionHealthCheck` — exercises a real PQ envelope roundtrip on every probe
  (encapsulate, HKDF, AES-256-GCM, decapsulate, decrypt) so any chain regression — missing
  keystore, wrong host KEK, BC version drift — surfaces as Unhealthy.
- `PostQuantumKeyManager.ListKeysAsync()` returning an ops-safe
  `IReadOnlyList<PostQuantumKeyDescriptor>` (id, algorithm, `CreatedAt`, `IsActive`) — non-secret,
  never names key material, suitable for `/admin` endpoints and metrics scrapers.
- **Pinned-seed ML-KEM-768 KAT** (`MlKemKatTests`): derive a keypair from a fixed 64-byte FIPS 203
  seed; SHA-256 the encoded `pk` and `sk`; compare to gold strings recorded against
  BouncyCastle 2.6.2. A future BC version that changes the FIPS 203 encoding fails CI loudly
  instead of silently shipping wire-format-incompatible envelopes. Plus a functional
  encapsulate/decapsulate roundtrip against the seeded keypair.
- **Wire-format pinned regression tests** (`WireFormatPinnedTests`): hand-crafted envelopes
  with hard-coded field bytes round-trip through `Encode`/`Decode` with field-for-field
  assertions; the encoded envelope's first 8 bytes are pinned to detect any header drift;
  `PostQuantumKeyPair` roundtrip + `ComputeKeyId` stability.
- Cross-platform **CI matrix** — ubuntu + windows + macOS — so the atomic-write retry path is
  exercised on every supported host on every PR.

### Tests

- **63/63** xUnit tests passing (was 48 in `preview.1`).

[0.1.0-preview.2]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.2

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

[0.1.0-preview.1]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.1
