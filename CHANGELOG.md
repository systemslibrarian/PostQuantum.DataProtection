# Changelog

All notable changes to `PostQuantum.DataProtection` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the explicit caveat that the
binary wire format may change in breaking ways across `0.x` minor versions. See
[`KNOWN-GAPS.md` §9](KNOWN-GAPS.md#9-wire-format-is-versioned-but-pre-10).

## [Unreleased]

## [1.0.1] — 2026-06-30

Patch: robustness + hygiene fixes from an external code review. **No wire-format change** — every
1.0.0 envelope decodes identically; a drop-in over 1.0.0.

### Fixed

- **Decryptor fails closed uniformly.** A malformed/truncated envelope (previously a leaked
  `FormatException`) and a structurally-valid-but-invalid envelope such as a wrong-sized KEM
  ciphertext (previously a leaked `ArgumentException`) now both surface as `CryptographicException`
  — the type ASP.NET Core Data Protection's key-ring loader expects, so it can isolate one corrupt
  element instead of taking an unexpected exception to the host.
- **Encryptor zeroes its plaintext buffer.** The serialized Data Protection key bytes are now zeroed
  after encryption (every other key/secret was already zeroed; this closes the one gap).
- **File store cold-start race.** `FilePostQuantumKeyStore` handles the concurrent first-writer
  file-creation race (`File.Move` TOCTOU) by converging to the documented last-write-wins instead of
  throwing an unhandled `IOException` at startup.

### Changed

- Bumped the `PostQuantum.KeyManagement` dependency to `1.0.1`.
- Corrected an overclaiming comment in `HybridCombiner` about parameter-set agility.

## [1.0.0] — 2026-06-30

**First stable release — code-complete and wire-format-frozen.** Depends on the stable
`PostQuantum.KeyManagement 1.0.0`. Two items earlier framed as GA blockers ship as documented
limitations rather than blockers (see [`KNOWN-GAPS.md` §D](KNOWN-GAPS.md)): no third-party
cryptographic audit yet, and the cloud-backed stores are tested but not yet production-proven.

### Changed (potentially breaking)

- **Default `Mode` is now `HybridKemMode.XWingHybrid`** (was `Hybrid`). The X-Wing combiner binds
  the ML-KEM ciphertext into the key derivation. Existing envelopes keep decrypting under whatever
  mode they were written with; only fresh encryptions change. `Hybrid` remains fully supported.
- **`RotationInterval` is now `TimeSpan?`** (was `TimeSpan`). `null` (the default) disables
  scheduled rotation; a non-null value must be strictly positive — `TimeSpan.Zero` or a negative
  value now throws at registration instead of silently disabling.

### Added

- **`AddPostQuantumDataProtection(...)`** on `IServiceCollection` — a one-call entry point mirroring
  `AddDataProtection` (three overloads: `Action<options>`, path, `IConfigurationSection`).
- **`ValidateOnStartup`** (default `true`) — eagerly initializes the chain at host startup via
  `PostQuantumStartupValidator`, so a missing KEK / wrong passphrase / unwritable keystore fails
  fast at boot with an actionable error.
- **`IRotationLock`** abstraction with a default no-op (`NullRotationLock`) and a Redis `SET NX`
  distributed lock (`RedisRotationLock`, registered by `AddPostQuantumDataProtectionRedis`) so
  scheduled rotation is single-leader across replicas. Proven by a multi-replica concurrency test.
- **`PostQuantum.DataProtection.Rotate`** trace activity (tags `pq.parameterSet`, `pq.newKeyId`).
- **CLI** — `pq-dp keys list`, `pq-dp keys export`, `pq-dp doctor`, `pq-dp verify` (all read-only,
  no secrets, no KEK required).
- **Testing package** — `AddPostQuantumDataProtectionTesting(HybridKemMode)` overload,
  `FakePostQuantumKeyStore.CorruptSecretKey` fail-closed injection, `DeleteAsync`/pruning support,
  and `Count`/`KeyIds` introspection.
- **Tests** — combiner known-answer (KAT) tests, a parameter-set agility matrix, a
  future-version-rejection test, and a Redis rotation-lock concurrency proof.
- **Docs** — [`docs/configuration.md`](docs/configuration.md),
  [`docs/troubleshooting.md`](docs/troubleshooting.md),
  [`docs/observability.md`](docs/observability.md), and the auditable
  [`docs/crypto-spec.md`](docs/crypto-spec.md).

### Frozen

- Envelope and keypair-token wire formats are frozen at version 1 for 1.0; decoders reject unknown
  versions and modes.

## [0.1.0-preview.5] — 2026-06-04

**BCL ML-KEM on `net10.0` + AOT compatibility.** Backward-compatible.

### Added

- **BCL ML-KEM path on `net10.0`** — operations route through
  `System.Security.Cryptography.MLKem` instead of BouncyCastle on the `net10.0` target.
  `MlKem` is partial across three files (`MlKem.cs`, `MlKem.Bcl.cs`, `MlKem.BouncyCastle.cs`)
  selected at compile time by `NET10_0_OR_GREATER`. Envelope byte format unchanged —
  envelopes written by a `net8.0` host decode correctly on a `net10.0` host and vice versa.
- **AOT compatibility on `net10.0`** — `IsAotCompatible=true` and `IsTrimmable=true` on the
  net10 target; zero `IL2026`/`IL3050` warnings. The one reflection-using API
  (`ProtectKeysWithPostQuantum(IConfigurationSection)`) carries
  `[RequiresUnreferencedCode]` + `[RequiresDynamicCode]` so the warning propagates cleanly.
- **`MlKem.GenerateKeyPairFromSeed`** — deterministic keypair generation from a 64-byte FIPS 203
  seed (`d ‖ z`). KAT tests now use this for path-agnostic verification.
- **`docs/aot.md`** rewritten as the per-target AOT audit.

### Changed

- `BouncyCastle.Cryptography` package reference is conditional —
  `Condition="'$(TargetFramework)' != 'net10.0'"`. Net10 consumers no longer pull in BC.
- Test project no longer references BouncyCastle directly; KATs route through `MlKem`.

### Closed in `KNOWN-GAPS.md`

- ✅ §C3 BCL ML-KEM on net10.0+
- ✅ §C4 AOT compatibility on net10.0

[0.1.0-preview.5]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.5

## [0.1.0-preview.4] — 2026-06-04

**Adoption pass + 4 roadmap items.** Backward-compatible.

### Added — adoption (Tier A + B from the "10/10 usable" list)

- **`ILogger<T>` integration** with pinned EventIds 1-23 across encryptor, decryptor, key
  manager, and the new rotation hosted service. `NullLogger` fallback.
- **Actionable error messages** naming the offending option, file path, and fix.
- **`ProtectKeysWithPostQuantum(IConfigurationSection)`** overload for appsettings.json-only
  wiring.
- **`PostQuantumRotationHostedService`** driven by `PostQuantumDataProtectionOptions.RotationInterval`.
  `TimeSpan.Zero` disables; any positive value enables scheduled rotation.
- **`PostQuantum.DataProtection.Testing`** package with `FakePostQuantumKeyStore` +
  `AddPostQuantumDataProtectionTesting()` for consumer unit tests — no Azure, no AWS, no disk.
- **`PostQuantum.DataProtection.OpenTelemetry`** package — one-line
  `.AddPostQuantumDataProtectionInstrumentation()` on `MeterProviderBuilder` /
  `TracerProviderBuilder`.
- **`PostQuantum.DataProtection.Aws`** package — AWS Secrets Manager-backed
  `IPostQuantumKeyStore`.
- **`pq-dp` dotnet tool** — `PostQuantum.DataProtection.Cli`. `pq-dp inspect <key.xml>`
  prints envelope routing fields. No secrets emitted.
- **Community files** — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue templates, PR
  template, `dependabot.yml`.
- **DocFX site + GitHub Pages workflow** for the rendered API reference.
- **`docs/migration.md`** for moving off DPAPI / Azure Key Vault key wrap / Certificate to PQ
  without disrupting live cookies.

### Added — roadmap items closed

- **§C1 Selectable ML-KEM parameter set** — `MlKemParameterSet { Kem512, Kem768, Kem1024 }`
  on `PostQuantumDataProtectionOptions.ParameterSet`. Existing keypairs keep decrypting under
  their original set; keypair id prefix reflects the set.
- **§C2 Retention / eviction API** — default-implemented `IPostQuantumKeyStore.DeleteAsync`
  (overridden by every shipped store) + `PostQuantumKeyManager.PruneOlderThanAsync(threshold)`.
  Refuses to delete the active keypair.
- **§C5 X-Wing combiner** — `HybridKemMode.XWingHybrid` using SHA3-256 over
  `(label ‖ mlKemSs ‖ classicalSs ‖ mlKemCt ‖ nonce)`. New `Mode` byte (=2); backward-compatible.
- **§C7 Redis-backed key store** — `PostQuantum.DataProtection.Redis` package with
  `RedisPostQuantumKeyStore` using `StackExchange.Redis`. One hash + one string. Natural pair
  with `PersistKeysToStackExchangeRedis`.

### Added — samples

- **`samples/WorkerService.Sample`** — `PostQuantum.DataProtection` outside ASP.NET Core.
- **`samples/Blazor.Sample`** — Blazor Server with PQ-protected circuit + cookie auth.
- **`samples/MultiReplica.Sample`** — two simulated replicas sharing one Key Vault, end to end.

### Changed

- `KNOWN-GAPS.md` rewritten with **§A Closed / §B Deliberate / §C Roadmap / §D Honest gates on
  1.0** structure.
- `README.md` rewritten to lead with the package + sample matrix, performance numbers, and
  observability table.

### Tests

- **100/100 across 5 suites** (was 81/81 across 3 in `preview.3`).

[0.1.0-preview.4]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.4

## [0.1.0-preview.3] — 2026-06-04

**Production-readiness pass.** Backward-compatible. No crypto-logic changes.

### Added

- **NIST ACVP / FIPS 203 KAT** (`AcvpKatTests`) pinning BouncyCastle's ML-KEM-768 against a real
  vector from
  [`post-quantum-cryptography/KAT`](https://github.com/post-quantum-cryptography/KAT).
  Standard-conformance verification, not self-consistency.
- **`System.Diagnostics.Metrics` integration** — `Meter("PostQuantum.DataProtection")` with
  counters and duration histograms, plus an `ActivitySource` for distributed tracing.
- **Concurrency stress tests** — 16-thread `Parallel.ForEachAsync` exercising encrypt /
  decrypt / `RotateAsync` plus a first-run race test.
- **Code coverage** — coverlet collector with CI gate at ≥ 85% line / ≥ 75% branch
  (current 89.5% / 78.6%).
- **Reproducible-build verification** in CI — repacks twice and asserts byte-identical SHA-256.
- **AOT/trimming audit** (`docs/aot.md`) — honest "not AOT-compatible because BC uses
  reflection."
- **BenchmarkDotNet harness** with numbers in `docs/benchmarks.md`.
- **Production deployment guide** (`docs/deployment.md`).
- **Property-based fuzz-lite tests** (`HostileInputContractTests`) — 30 000 random byte arrays
  through both decoders on every CI run.
- **SharpFuzz harness** in `fuzz/` for AFL-driven exploration.
- **`PostQuantum.DataProtection.AzureKeyVault`** companion package — Azure Key Vault-backed
  `IPostQuantumKeyStore` with `DefaultAzureCredential`.

### Tests

- **81 tests passing** across 2 suites (was 48 in `preview.2`).

[0.1.0-preview.3]: https://github.com/systemslibrarian/PostQuantum.DataProtection/releases/tag/v0.1.0-preview.3

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
