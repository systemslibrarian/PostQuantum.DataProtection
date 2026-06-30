# Future

This document is the public roadmap. It is more concrete than a wish list and less binding than a
promise — every item is something we believe is worth doing, in a rough order of priority, with
the design considerations we already know about.

The principle: **do not break callers, do not regress the security story, ship things in real use
before declaring `1.0`.**

## `1.0` — shipped

**Status: `1.0.0` — first stable release.** Roadmap items 1–6 below all shipped (selectable
parameter sets, Azure Key Vault / AWS / Redis stores, retention/pruning, the X-Wing combiner now the
default, and the FIPS marker package), the wire format is frozen, SemVer is in force, and the
dependency is the stable `PostQuantum.KeyManagement 1.0.0`.

Two items earlier framed as GA blockers shipped as **documented limitations** instead (posture
recorded in [`KNOWN-GAPS.md` §D](KNOWN-GAPS.md)) — they are post-1.0 work, not release blockers:

1. **External cryptographic review** — the auditable target is [`docs/crypto-spec.md`](docs/crypto-spec.md).
2. **Cloud-backed store proven in real production** — the stores ship and are tested (including a
   multi-replica rotation-lock concurrency proof); a named production deployment is still wanted.

## Roadmap (priority-ordered)

### 1. Selectable ML-KEM parameter set

- Add `MlKemParameterSet { Kem512, Kem768, Kem1024 }` and expose it on
  `PostQuantumDataProtectionOptions`.
- The internal `MlKem` type is the only file that talks parameters; the wire-format already
  carries `KemAlgorithm` as a string so old envelopes will keep decoding.
- The `KeyId` derivation prefix becomes parameter-aware: `"pq-mlkem512-…"`, `"pq-mlkem768-…"`,
  `"pq-mlkem1024-…"`. Old `pq-mlkem768-…` ids continue to route correctly.

### 2. Azure Key Vault PQ key store (`PostQuantum.DataProtection.AzureKeyVault`)

- New package; depends on `Azure.Security.KeyVault.Secrets` and on the core package.
- Implements `IPostQuantumKeyStore` by storing the keypair token as a secret value in a Key Vault
  secret per key id, with an additional "active" secret pointing at the live one.
- The secret-key wrapping inside the token is unchanged — Key Vault sees the same envelope-encrypted
  blob the file store sees. Key Vault is a durable persistence target, not a new trust boundary.
- DI: `services.AddSingleton<IPostQuantumKeyStore>(new AzureKeyVaultPostQuantumKeyStore(...))`.

### 3. AWS KMS PQ key store (`PostQuantum.DataProtection.Aws`)

- Same shape as (2). Implementation alignment lock the abstraction.
- Storage target: AWS Secrets Manager (parameter store is also a candidate; Secrets Manager is
  the simpler match because it returns the value verbatim).

### 4. Retention / eviction policy

- Add `PostQuantumDataProtectionOptions.PqKeyRetention` — a count, or an age, or both.
- The store exposes a new `PruneAsync(...)` method; the manager calls it on rotation after a
  policy check.
- **The hard part is not the API; it is the semantics.** Pruning a PQ keypair invalidates every
  Data Protection element ever wrapped under it. The right default may be "never prune
  automatically; expose `PruneAsync` for the operator." We will document the trade-offs and ship
  a manual-only knob first.

### 5. X-Wing-style hybrid combiner

- Today's combiner is HKDF-SHA-256 over `mlKemSs || classicalSs` with a domain-separation label.
- The X-Wing combiner (per `draft-connolly-cfrg-xwing-kem`) hashes both shared secrets plus
  context-binding fields with SHA-3. It is a sharper construction in some adversary models.
- Add as `HybridCombiner.Mode { Hkdf, XWing }`, default to the existing HKDF for compatibility.
- Bump the envelope `Mode` byte values so an XWing envelope is statically distinguishable from
  the existing two.

### 6. BC FIPS module integration path for FIPS 140-3 deployments

- The standard BC build is not a FIPS module; BC ships a separate
  `BouncyCastle.NetCoreSdk.Fips` distribution.
- A `PostQuantum.DataProtection.Fips` shim package would route `MlKem` calls through the FIPS
  module. Two open questions:
  - Licensing/distribution: BC FIPS is a separate licensing path. Document that consumers obtain
    it themselves and reference it directly; we do not redistribute.
  - Per-target: the FIPS module's framework support may not match net8.0 / net9.0 / net10.0
    exactly; the shim may need to multi-target differently.

### 7. External cryptographic review

- Gated behind (1)–(3). Targeted scope:
  - The envelope wire format and hybrid combiner.
  - The XML wrapper and decoder hostile-input handling.
  - The PQ keypair persistence and SK-wrap construction.
  - The interplay with `PostQuantum.KeyManagement`'s envelope-encryption flow.
- Output: a public report linked from `SECURITY.md` and a fixed-issues changelog.

### 8. `1.0`

- Lock the wire format. Any post-`1.0` wire-format change ships a new `FormatVersion` and a
  documented migration window — never a silent break.
- Wire-format SemVer applies: changes to the binary layout are major-version bumps.
- The "preview" badge in the README disappears.

## What we are not planning to do

- **A new symmetric primitive.** AES-256-GCM stays. ChaCha20-Poly1305 swap is a non-goal unless a
  real reason to add it appears (constant-time fallback on CPUs without AES-NI is the obvious
  one, but every relevant deployment target has AES-NI today).
- **A new key-derivation primitive.** HKDF-SHA-256 stays. The (5) X-Wing combiner is an addition,
  not a replacement.
- **In-process PQ session-key negotiation.** This library is about *at-rest* wrapping. If you
  need PQ session negotiation, look at TLS 1.3 hybrid groups landing in cloud frontends.
- **A homegrown ML-KEM implementation.** BouncyCastle stays. We will not re-implement primitives.

---

*To God be the glory — 1 Corinthians 10:31.*
