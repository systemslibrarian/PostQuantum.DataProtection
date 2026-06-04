# Security Policy

Cryptography software earns trust by being honest about its limits. This document explains how to
report a problem and what guarantees the library does — and does not — make today. For the
running list of limitations, see [KNOWN-GAPS.md](KNOWN-GAPS.md). For the precise statement of what
we defend against, see [`docs/threat-model.md`](docs/threat-model.md).

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Use **GitHub Security Advisories** ("Report a vulnerability") on this repository, or
- email the maintainer privately.

Please include enough detail to reproduce: affected version, target framework, a minimal repro,
and the impact you observed. You will get an acknowledgement, and we will keep you informed as we
investigate, fix, and (with credit, if you wish) disclose.

This is a faith-and-craft project — responses are best-effort, but security reports are always
triaged first.

## Supported versions

While in `0.x` preview, only the **latest released version** receives security fixes. There is no
back-porting to older previews before `1.0`. The `1.0` backport policy will be published at that
release; see [`future.md`](future.md) for the 1.0 checklist.

| Version           | Supported |
| ----------------- | --------- |
| `0.1.0-preview.*` | ✅        |
| older previews    | ❌        |

## What this library protects

- **Confidentiality and integrity of persisted Data Protection keys.** Every `<encryptedSecret>`
  element written by ASP.NET Core Data Protection is wrapped in an authenticated, hybrid
  ML-KEM-768 + AES-256-GCM envelope. Tampering is detected at the AES-GCM tag; a modified envelope
  fails to decrypt rather than yielding attacker-influenced key material.
- **Harvest-now-decrypt-later resistance.** Even if the on-disk key store is exfiltrated today, an
  adversary who eventually obtains a cryptographically-relevant quantum computer still has to
  defeat AES-256-GCM (Grover-bounded ≈ 128-bit post-quantum margin) on the classical layer, *and*
  the host KEK derived from Argon2id over a passphrase they do not have.
- **Strong content keys.** The per-envelope AES-256 key is HKDF-SHA-256-derived from the
  ML-KEM-768 shared secret and (in hybrid mode) a 256-bit classical secret from a CSPRNG-backed
  `IContentKeyProvider` DEK. HKDF salt is the per-envelope 96-bit AES-GCM nonce, so even
  many-payload reuse of the same KEM keypair yields a fresh key per payload.
- **Long-lived PQ secret-key confidentiality at rest.** The ML-KEM private key is never written
  to disk in plaintext. The keystore file holds the public key in the clear and the secret key
  wrapped via the same `PostQuantum.KeyManagement` envelope used elsewhere in the family.
- **Hostile-input resistance.** `HybridKemEnvelope.Decode` and `PostQuantumKeyPair.Decode` cap
  every length-prefixed field at 1 MiB and use overflow-safe bounds arithmetic so a malformed
  envelope cannot trigger huge allocations or out-of-bounds reads. `TryDecode` overloads exist for
  inputs from untrusted sources.
- **Boundary validation.** Empty inputs and structurally-invalid envelopes are rejected with
  clear `ArgumentException` / `FormatException` / `CryptographicException` at the library
  boundary, before any further cryptographic work runs.
- **Memory hygiene.** Plaintext ML-KEM shared secrets, plaintext classical secrets, plaintext
  derived AES keys, and the plaintext ML-KEM secret key are zeroed
  (`CryptographicOperations.ZeroMemory`) as soon as they are no longer needed.
- **Safe diagnostic output.** Every record that carries byte arrays
  (`HybridKemEnvelope`, `PostQuantumKeyPair`) overrides `ToString()` to redact byte content as
  `<NN bytes>`. Log lines that include these records cannot leak ciphertext.
- **Cross-platform atomic file persistence.** `FilePostQuantumKeyStore` writes via temp-file +
  `File.Replace` with a bounded retry on Windows-specific `IOException` from concurrent readers,
  so a crash mid-rotation cannot leave a torn keystore on disk.
- **Pinned-and-patched transitive dependency.**
  `Microsoft.AspNetCore.DataProtection.Extensions` transitively brings in
  `System.Security.Cryptography.Xml`; the unpatched 8.0.x line carries
  [GHSA-37gx-xxp4-5rgx](https://github.com/advisories/GHSA-37gx-xxp4-5rgx) and
  [GHSA-w3x6-4m5h-cxqf](https://github.com/advisories/GHSA-w3x6-4m5h-cxqf). The `.csproj` pins
  `System.Security.Cryptography.Xml` to the patched 8.0.3 explicitly so a transitive resolution
  cannot land on the unpatched version.

## What it does NOT protect against (today)

- **A compromised host.** If an attacker can read your process memory while a Data Protection key
  is in use, no library can save the keys in use at that moment.
- **Weak host passphrases.** Argon2id raises the cost of guessing the classical KEK; it cannot
  rescue a low-entropy secret. The `PostQuantum.KeyManagement`
  [SECURITY.md](https://github.com/systemslibrarian/PostQuantum.KeyManagement/blob/main/SECURITY.md#recommended-argon2id-profile-in-production)
  documents the recommended Argon2id profile.
- **FIPS 140 validation.** This library uses the standard BouncyCastle build, not the BouncyCastle
  FIPS module. Deployments under FIPS 140-3 compliance regimes should not use this release;
  routing the ML-KEM operations through a validated module is in [`future.md`](future.md).
- **A compromised host KEK.** If both the keystore file and the passphrase that derives the host
  KEK are exfiltrated, the chain ends at the classical layer.
- **Cross-party PQ key exchange.** This library is for *at-rest* wrapping; it does not negotiate
  PQ session keys between parties. See [KNOWN-GAPS.md §4](KNOWN-GAPS.md#4-not-a-cross-party-kem).
- **External audit.** No third-party cryptographic review yet. The engagement plan is in
  [`future.md`](future.md).

## Recommended deployment posture

- **Treat the keystore file as a database.** Back it up. Losing the keystore means losing the
  ability to decrypt every Data Protection key wrapped under any keypair in that ring.
- **Use a strong host KEK passphrase.** Long, high-entropy, drawn from a secret manager — never
  checked-in configuration.
- **Pick `KekWorkFactor.Moderate` or higher in production.** See
  [`PostQuantum.KeyManagement`'s
  guidance](https://github.com/systemslibrarian/PostQuantum.KeyManagement/blob/main/SECURITY.md#recommended-argon2id-profile-in-production).
- **Persist Data Protection keys to durable storage**, not container-local disk. The
  `PersistKeysToFileSystem(...)` directory in the quick-start above is fine for examples; in
  production point it at a mounted volume, network share, or `PersistKeysToAzureBlobStorage(...)`
  / equivalent.
- **Run on hardened hosts.** OS-level memory protections, no untrusted plugins in the process,
  least-privilege filesystem ACLs on the keystore and key directory.

## Cryptographic dependencies

- **ML-KEM-768** (FIPS 203) from
  [`BouncyCastle.Cryptography`](https://www.bouncycastle.org/) ≥ 2.6.2.
- **AES-256-GCM**, **HKDF-SHA-256**, **SHA-256**, and the CSPRNG come from the .NET base class
  library (`System.Security.Cryptography`).
- **Argon2id** (transitive via `PostQuantum.KeyManagement` → `Konscious.Security.Cryptography.Argon2`).

We do not ship our own implementations of cryptographic primitives.

## Responsible disclosure

We support coordinated disclosure and are happy to credit reporters. Thank you for helping keep
users safe.

---

*To God be the glory — 1 Corinthians 10:31.*
