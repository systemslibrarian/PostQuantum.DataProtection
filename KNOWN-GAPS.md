# Known Gaps

This file is the honest counterpart to the README. It lists what `PostQuantum.DataProtection` does
**not** do yet, what is deliberately out of scope, and where the design has sharp edges. If
something here surprises you *after* you shipped, that is a documentation bug — please open an
issue.

Status as of **`0.1.0-preview.1`**.

For the precise threat model and the security invariants we DO commit to, see
[`docs/threat-model.md`](docs/threat-model.md). For the concrete plan to close the cloud-store,
FIPS, and audit gaps below, see [`future.md`](future.md).

## 1. Single KEM, single parameter set

- **ML-KEM-768 only.** ML-KEM-512 (smaller envelopes, lower security category) and ML-KEM-1024
  (larger envelopes, higher category) are not selectable in this release. The choice is hard-coded
  to `MLKemParameters.ml_kem_768` so reviewers can read the security level from the source.
- **No alternative KEMs.** HQC, BIKE, NTRU, X-Wing — none ship here. If you need an alternative
  PQ primitive (or a hybrid where the classical layer is also asymmetric, e.g. X25519), this
  release is not a fit.
- Parametrisation is roadmap. The internal abstraction is already split (`MlKem` is the only
  KEM-specific file), so adding a second algorithm is mechanical when the time comes.

## 2. No cloud-backed PQ key stores yet

- Only the file-backed `FilePostQuantumKeyStore` ships. Azure Key Vault, AWS KMS, GCP KMS, and
  HSM-backed stores are roadmap.
- The extension point is already there — implement `IPostQuantumKeyStore`. The bundled file store
  is the reference implementation: see how it handles atomic writes (temp file + `File.Replace`
  with bounded retry on Windows-specific `IOException`) for the shape a production-grade store
  should match.
- Cloud stores will ship as separate packages
  (`PostQuantum.DataProtection.AzureKeyVault`, etc.) so the core package stays dependency-light.

## 3. Not FIPS 140-validated

- The library uses the **standard** BouncyCastle build for ML-KEM. BouncyCastle distributes a
  separate **FIPS 140-3-validated** module, but this release does not link against it.
- Deployments under FIPS 140-3 compliance regimes should not use this release.
- A path that routes ML-KEM through the BC FIPS module — without forcing every consumer to pay
  the FIPS module's licensing/distribution cost — is in [`future.md`](future.md).

## 4. Not a cross-party KEM

- This library is for **at-rest** wrapping of Data Protection keys. It does **not** negotiate
  post-quantum session keys between two parties on the wire (no TLS hybrid groups, no IKE PQ
  exchange, no Noise hybrid handshakes). If that is what you need, look at the TLS 1.3 hybrid
  groups landing in cloud frontends and the
  [hybrid PQ ECH](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) work.
- The PQ public key never leaves the host in the documented flow. If you choose to extract it for
  a separate purpose, you are off the supported path.

## 5. PQ keypair rotation must keep old keys readable

- The bundled `FilePostQuantumKeyStore` keeps every keypair ever generated so payloads encrypted
  to older PQ public keys still decrypt after a rotation. This is by design — Data Protection
  rotates its own keys aggressively, and we should not silently invalidate yesterday's session
  cookies.
- The keystore file grows by ~3.5 KiB per rotation (ML-KEM-768 sizes plus envelope overhead).
  At one rotation per quarter that is well under a kilobyte per month; at one per day it is still
  trivial for several years. There is currently **no eviction**: if you want to prune very old
  keypairs you must do so manually, accepting that any Data Protection keys still wrapped under
  those PQ keypairs become unreadable.
- A documented retention/eviction story is on the roadmap.

## 6. Sync-over-async at the IXmlEncryptor seam

- ASP.NET Core's `IXmlEncryptor` / `IXmlDecryptor` contracts are **synchronous**. The
  post-quantum operations (ML-KEM encapsulation/decapsulation, AES-GCM, optional classical KEK
  unwrap) are awaited via `.AsTask().GetAwaiter().GetResult()` inside the encryptor/decryptor.
- This is the same pattern Data Protection itself uses for its built-in encryptors, runs on the
  startup-time key-loader thread, and is not a request-path hot loop. ML-KEM-768 encapsulation is
  microseconds on modern hardware; the classical layer adds a single AES-GCM unwrap.
- A request that hot-loops through new Data Protection keys at extreme rate could in theory
  observe the cost. If that ever shows up in profiling, the answer is the same as for stock Data
  Protection: warm the key ring at startup, not under load.

## 7. The host KEK is still load-bearing

- The classical layer is a `WrappedContentKey` from `PostQuantum.KeyManagement`. Its strength is
  bounded by the strength of the host passphrase and the Argon2id profile. If both the keystore
  file and the host passphrase are exfiltrated, the chain ends at the classical layer.
- This is by design — the library refuses to invent a new secret-storage primitive. The
  recommended posture is a strong passphrase, in a real secret store, at `Moderate` or higher
  Argon2id work factor.

## 8. Not independently audited yet

- Written with care, automated tests, hostile-input tests, static analysers, and a published
  threat model — but it has **not** had a third-party cryptographic audit. Treat `0.x` accordingly.
- The plan to commission a review is laid out in [`future.md`](future.md). It is gated behind
  the cloud-store extension point landing — reviewing a moving target wastes the reviewer's time.

## 9. Wire format is versioned but pre-1.0

- The envelope format (`HybridKemEnvelope`, version 1) and the keypair format
  (`PostQuantumKeyPair`, version 1) carry explicit version bytes and the decoder rejects unknown
  versions. We will keep `Decode` able to read prior versions whenever feasible.
- That said, **pre-1.0 we may bump these versions in breaking ways** when something genuinely
  warrants it. We will name the change in `PackageReleaseNotes` and the README status section,
  and ship a migration note in `CHANGELOG.md`. Do not depend on byte-for-byte compatibility
  across `0.x` minor versions for now.

---

## Roadmap (not promises, intentions)

- ✅ **Done in `0.1`:** ML-KEM-768 + AES-256-GCM hybrid envelope; one-line
  `ProtectKeysWithPostQuantum`; atomic file-backed key store; sync-safe IXmlEncryptor; safe
  diagnostics; hostile-input-resistant decoders; threat model; SBOM-friendly metadata;
  pinned-and-patched `System.Security.Cryptography.Xml`.
- Cloud-backed PQ key stores (Azure Key Vault, AWS KMS, GCP KMS) as separate packages.
- Selectable ML-KEM parameter set (512 / 768 / 1024).
- Optional X-Wing-style hybrid combiner alongside the existing HKDF combiner.
- Eviction / retention policy for old PQ keypairs.
- BC FIPS module integration path for FIPS 140-3 deployments.
- External cryptographic review.
- `1.0` once the above are in real use.

---

*To God be the glory — 1 Corinthians 10:31.*
