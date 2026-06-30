# Known gaps — what's deliberate, what's coming, what's done

This file is the honest counterpart to the README. It's organised the way a reviewer reads it:

- **§A Closed.** Things people sometimes ask about that the library actually ships.
- **§B Deliberate.** Scope decisions we have made and don't intend to change.
- **§C Roadmap.** Things we know would be useful and are working toward.
- **§D Honest gates.** Things that block `1.0` and are calendar-time, not code-time.

We would rather under-claim and ship than overstate. If something here surprises you *after* you
shipped, that is a documentation bug — please open an issue.

Status as of **`1.0.0`**.

---

## §A Closed in `1.0.0`

The 1.0 release is code-complete and wire-format-frozen. What changed since the preview series:

- ✅ **X-Wing combiner is the default.** `HybridKemMode.XWingHybrid` is now the default `Mode`
  (was `Hybrid`). It binds the ML-KEM ciphertext into the key derivation. Existing envelopes keep
  decrypting under whatever mode they were written with — only fresh encryptions change. `Hybrid`
  remains fully supported.
- ✅ **Wire format frozen.** Envelope and keypair-token formats are frozen at version 1 for 1.0;
  decoders reject unknown versions/modes (see [`docs/crypto-spec.md`](docs/crypto-spec.md)), with
  known-answer tests for every combiner derivation.
- ✅ **One-call entry point + fail-fast.** `services.AddPostQuantumDataProtection(...)` (mirrors
  `AddDataProtection`). `ValidateOnStartup` (default on) eagerly initializes the chain at boot so a
  bad passphrase / unwritable keystore / missing KEK fails fast with an actionable error.
- ✅ **Multi-replica rotation lock.** `IRotationLock` abstraction + a Redis `SET NX` distributed
  lock (`PostQuantum.DataProtection.Redis`) so scheduled rotation is single-leader across replicas;
  proven by a concurrency test. `RotationInterval` is now `TimeSpan?` (null disables; zero/negative
  is rejected at registration rather than silently disabling).
- ✅ **Operator CLI.** `pq-dp` gained `keys list`, `keys export`, `doctor`, and `verify` — all
  read-only, no secrets, no KEK required.
- ✅ **Testing package.** Mode overload on `AddPostQuantumDataProtectionTesting`,
  `FakePostQuantumKeyStore.CorruptSecretKey` fail-closed injection, pruning, and introspection.
- ✅ **Docs.** Configuration reference, troubleshooting / incident-response, observability, and an
  auditable crypto specification.

## §A Closed in `0.1.0-preview.5`

- ✅ **§C3 BCL ML-KEM on `net10.0+`.** ML-KEM operations run through
  `System.Security.Cryptography.MLKem` on the `net10.0` target; `net8.0` and `net9.0` continue
  to use BouncyCastle. The `MlKem` static class is partial across three files
  (`MlKem.cs`, `MlKem.Bcl.cs`, `MlKem.BouncyCastle.cs`) selected at compile time. Envelope
  byte-format is unchanged — an envelope written by a `net8.0` host decodes correctly on a
  `net10.0` host and vice versa.
- ✅ **§C4 AOT compatibility on `net10.0`.** `IsAotCompatible=true` and `IsTrimmable=true` on
  the `net10.0` target. The library emits zero `IL2026` / `IL3050` warnings on net10. The one
  reflection-using public method (`ProtectKeysWithPostQuantum(IConfigurationSection)`) carries
  `[RequiresUnreferencedCode]` + `[RequiresDynamicCode]` so the warning propagates to the
  caller. See [`docs/aot.md`](docs/aot.md).

## §A Closed in `0.1.0-preview.4`

In addition to the items below, preview.4 closed four §C roadmap items in one push:

- ✅ **§C1 Selectable ML-KEM parameter set.** `MlKemParameterSet { Kem512, Kem768, Kem1024 }` on
  `PostQuantumDataProtectionOptions.ParameterSet`. Existing keypairs continue to decrypt under
  their original set regardless of the new value.
- ✅ **§C2 Retention / eviction.** `IPostQuantumKeyStore.DeleteAsync` (default-implemented as
  not-supported, overridden by every shipped store) and
  `PostQuantumKeyManager.PruneOlderThanAsync(threshold)` with safety-first semantics — refuses to
  delete the active keypair.
- ✅ **§C5 X-Wing-style combiner.** New `HybridKemMode.XWingHybrid` value. SHA3-256 over the
  ML-KEM ciphertext, ML-KEM shared secret, classical secret, and domain label. Sharper combiner
  in some adversary models; backward-compatible (old envelopes keep decoding).
- ✅ **§C7 Redis-backed PQ key store.** `PostQuantum.DataProtection.Redis` package — natural pair
  with `PersistKeysToStackExchangeRedis` so the DP keys and the PQ keypairs that wrap them live
  in the same Redis instance.

### Other

These are listed because earlier previews didn't have them — if you read older blog posts or
gists, they may say otherwise. Today they ship.

- ✅ **Cloud-backed PQ key stores.** `PostQuantum.DataProtection.AzureKeyVault` and
  `PostQuantum.DataProtection.Aws` both ship as separate packages with the same shape: one secret
  per keypair, one "active" pointer secret, a narrow client seam so unit tests don't need a real
  cloud account.
- ✅ **Test fakes for consumer projects.** `PostQuantum.DataProtection.Testing` ships
  `FakePostQuantumKeyStore` plus the one-line `AddPostQuantumDataProtectionTesting()` so your
  tests don't have to stand up the full chain.
- ✅ **OpenTelemetry one-liner.** `PostQuantum.DataProtection.OpenTelemetry` wires the built-in
  Meter and ActivitySource into a `MeterProviderBuilder` / `TracerProviderBuilder` with one call.
- ✅ **`ILogger<T>` integration** with pinned EventIds across encryptor, decryptor, key manager,
  and the hosted rotation service. `NullLogger` fallback when logging isn't configured.
- ✅ **Scheduled PQ keypair rotation** via the `RotationInterval` option on
  `PostQuantumDataProtectionOptions`. `TimeSpan.Zero` disables; any positive value enables.
- ✅ **`appsettings.json`-only wiring.** `ProtectKeysWithPostQuantum(IConfigurationSection)`
  binds the option object directly from configuration.
- ✅ **Actionable error messages.** Every option / file / wiring error names the offending
  configuration key, the file path involved, the fix, and a doc reference.
- ✅ **CLI diagnostics tool.** `PostQuantum.DataProtection.Cli` ships the `pq-dp` global tool:
  `pq-dp inspect <key.xml>` prints envelope routing fields and byte sizes without exposing any
  secret material.
- ✅ **Migration guide** for moving off DPAPI, Azure Key Vault key wrap, or certificate-based DP
  protection without invalidating live cookies.
- ✅ **DocFX site + GitHub Pages workflow** for the rendered API reference.
- ✅ **NIST ACVP / FIPS 203 KAT** against a published vector — the FIPS-conformance test, not the
  "self-consistent" test.

## §B Deliberate scope

These are decisions we have made and are not planning to change. None of them are accidents.

### B1. Secure-by-default modes only; no path to an insecure configuration

The KEM family is ML-KEM (FIPS 203) only, with selectable parameter sets
(`MlKemParameterSet { Kem512, Kem768, Kem1024 }`, default `Kem768`). The production content-key
combiners are `XWingHybrid` (default; SHA3-256 binding the ML-KEM ciphertext) and `Hybrid`
(HKDF-SHA-256 over the ML-KEM secret concatenated with the classical secret). `MlKemOnly` exists
for tests/KATs and callers without a classical KEK. There is deliberately no configuration that
produces a weak wrap — that is the "secure by default, not configurable to insecurity" stance.

### B2. The host KEK is load-bearing

The classical layer wraps the PQ secret key with a `PostQuantum.KeyManagement`
`IContentKeyProvider`. The strength of that wrap is bounded by the strength of the host
passphrase and the chosen Argon2id profile. If both the keystore *and* the passphrase are
exfiltrated, the chain ends. This is by design — we don't invent a new secret-storage primitive.
Use a strong passphrase, in a real secret store, at `KekWorkFactor.Moderate` or higher.

### B3. Storage extension lives outside the core

`IPostQuantumKeyStore` is the only seam we ship for "where do the keypairs live." Cloud-store
implementations are separate packages so the core stays dependency-light. Redis, file system,
cloud blob, KMS-bound — implement the interface or use a shipped one. We don't pull in the AWS
SDK to use file storage.

### B4. We don't ship our own primitives

ML-KEM comes from BouncyCastle (FIPS 203). AES-256-GCM, HKDF-SHA-256, SHA-256, HMAC-SHA-256, and
the CSPRNG come from `System.Security.Cryptography`. Argon2id comes from
`Konscious.Security.Cryptography.Argon2` (transitive via `PostQuantum.KeyManagement`). We will
not re-implement primitives.

### B5. The library is for at-rest wrapping

It wraps the ASP.NET Core Data Protection key directory and the long-lived ML-KEM keypair. It
does **not** negotiate post-quantum session keys between two parties on the wire. If you want
TLS 1.3 hybrid groups, that's a network-stack concern — different layer. The PQ public key in
this library does not leave the host in the supported flow.

## §C Roadmap

Things we know would be useful and are working toward, in rough priority order. None of these are
promises; all of them are intentions backed by some thought already.

### C6. FIPS 140-3 path via the BC FIPS module

A `PostQuantum.DataProtection.Fips` shim that routes ML-KEM through the BouncyCastle FIPS
module. Two open questions: licensing / distribution (BC FIPS is a separate licensing path) and
per-target framework support. Consumers under FIPS 140-3 compliance regimes shouldn't deploy
`0.1.0-preview.*` until this lands.

## §D Honest limitations carried into 1.0

`1.0.0` is shipped: the public API and the wire formats are **frozen**, SemVer is in force, and the
dependency on `PostQuantum.KeyManagement` is the stable `1.0.0`. Two items that earlier drafts framed
as GA blockers were shipped as **documented limitations** instead — they are real, they are honest,
and they are on the post-1.0 roadmap. They do not reduce the cryptographic claim; they bound the
*assurance* around it.

- [x] **Wire format frozen + SemVer commitment** — done. Any post-1.0 format change bumps
      `HybridKemEnvelope.CurrentFormatVersion` and is a major-version event.
- [x] **Stable classical-layer dependency** — depends on `PostQuantum.KeyManagement 1.0.0`.
- [ ] **External cryptographic review** — limitation (below).
- [ ] **Cloud store proven in production** — limitation (below).

### D1. Not yet independently audited

`1.0.0` ships **without** a third-party cryptographic audit. It is written with care, automated
tests, static analysers, hostile-input tests, a fuzz harness, NIST ACVP / FIPS 203 KATs, combiner
known-answer tests, a published [threat model](docs/threat-model.md), and an auditable
[crypto spec](docs/crypto-spec.md) — but no external review. This is a documented limitation, not a
hidden one; weigh it against your own risk tolerance. The plan to commission a review is in
[`future.md`](future.md) — it is post-1.0 work.

### D2. Cloud-backed stores not yet production-proven

`PostQuantum.DataProtection.AzureKeyVault`, `.Aws`, and `.Redis` are built and tested (including a
multi-replica rotation-lock concurrency proof), but none has yet been run in a named production
deployment. The abstraction (`IPostQuantumKeyStore`) is frozen at 1.0; if real production use later
reveals a gap, it will be addressed in a post-1.0 minor without breaking the wire format.

---

*To God be the glory — 1 Corinthians 10:31.*
