# Threat Model

This document states what `PostQuantum.DataProtection` defends against, what it deliberately does
not defend against, and the security invariants the library is designed to hold. It is the
precise statement that [`README.md`](../README.md) and [`SECURITY.md`](../SECURITY.md) summarise.

Status as of **`0.1.0-preview.1`**.

## What the library is

A pluggable `IXmlEncryptor` / `IXmlDecryptor` pair for ASP.NET Core Data Protection. Each
persisted Data Protection key (cookie key, antiforgery key, session-ticket key, any
`IDataProtector` payload at rest) is wrapped in an authenticated envelope:

1. The host generates a long-lived **ML-KEM-768** keypair on first run. The secret key is
   envelope-encrypted under a `PostQuantum.KeyManagement` `IContentKeyProvider` (Argon2id KEK +
   AES-256-GCM) and persisted to `keys/pq-keystore.txt`.
2. On every encryption, the encryptor encapsulates a fresh shared secret against the active PQ
   public key, mints a fresh classical DEK from the host `IContentKeyProvider`, derives the
   per-envelope AES-256 key via HKDF-SHA-256 over (ML-KEM secret || classical DEK secret), and
   AES-256-GCM-encrypts the original XML payload.
3. The on-disk envelope carries: format version, mode, KEM algorithm label, PQ key id, ML-KEM
   ciphertext, classical wrapped DEK token, AES-GCM nonce, tag, and ciphertext.

## Attacker model

The library defends against the following adversaries (A1 → A6 in increasing capability):

| ID  | Capability                                                                                 |
| --- | ------------------------------------------------------------------------------------------ |
| A1  | A network adversary reading TLS traffic to or from the host.                               |
| A2  | A passive observer of the on-disk key directory (a stolen backup, a leaked S3 bucket).     |
| A3  | An active attacker who can modify bytes in the on-disk key directory.                      |
| A4  | A future adversary with a cryptographically-relevant quantum computer (CRQC) and the bytes from A2 ("harvest now, decrypt later"). |
| A5  | An adversary who can read the on-disk PQ keystore file in addition to the key directory.   |
| A6  | An adversary who has the host KEK passphrase, but not the running process.                 |

The library does **not** defend against:

| ID  | Capability                                                                                 |
| --- | ------------------------------------------------------------------------------------------ |
| B1  | An attacker who reads the running process's memory (debuggers, kernel-level malware, side-channels at the host level). |
| B2  | An attacker who has both the on-disk keystore AND the host KEK passphrase.                 |
| B3  | An attacker who controls the host's CSPRNG.                                                |
| B4  | An attacker who controls the host's clock to the point of forging Data Protection key activation/expiration windows (a pure Data Protection concern). |

## Security invariants

The following 10 invariants are what the library is designed to hold. Each one corresponds to one
or more tests in `tests/PostQuantum.DataProtection.Tests`.

1. **Authenticated wrapping.** Every Data Protection element wrapped by this library is
   authenticated by AES-256-GCM with a 128-bit tag. Any modification of the envelope bytes
   produces a `CryptographicException` at the GCM verify step, never silent plaintext.
   *(A3 defended; tested in `EnvelopeTamperingTests`.)*

2. **Confidentiality under harvest-now-decrypt-later.** An adversary in possession of every byte
   the library has ever written to disk has to defeat **both** ML-KEM-768 *and* the classical
   AES-256-GCM wrap under the host KEK to recover the underlying Data Protection key. Neither
   layer is sufficient on its own.
   *(A4 defended in hybrid mode; tested via `HybridKemEnvelopeTests` and the wire-format separation
   between `KemCiphertext` and `ClassicalWrappedKeyToken`.)*

3. **No plaintext PQ secret key at rest.** The ML-KEM secret key is never written to disk in the
   clear. The keystore file holds it as an opaque blob whose inner contents are AES-256-GCM
   ciphertext under a DEK that is itself wrapped by the host KEK.
   *(A2, A5 defended; tested via `KeyStoreRoundtripTests` plus a "raw file has no SK bytes" assertion.)*

4. **No plaintext key material in long-lived buffers.** Plaintext ML-KEM shared secrets, plaintext
   classical DEK bytes, plaintext derived AES keys, and plaintext PQ secret keys are zeroed
   (`CryptographicOperations.ZeroMemory`) as soon as they are no longer needed.
   *(B1 best-effort mitigation; documented as best-effort because the managed runtime can copy
   buffers we cannot reach.)*

5. **Fresh per-envelope key material.** Every encryption produces a fresh ML-KEM encapsulation, a
   fresh classical DEK (in hybrid mode), a fresh 96-bit AES-GCM nonce, and therefore a fresh
   derived AES-256 key. Repeated encryptions of identical plaintexts produce statistically
   independent ciphertexts.
   *(B3 mitigated up to CSPRNG strength; tested in `RoundtripTests.RepeatedEncryption_*`.)*

6. **Hostile-input resistance.** `HybridKemEnvelope.Decode` and `PostQuantumKeyPair.Decode` cap
   every length-prefixed field at 1 MiB and use overflow-safe bounds arithmetic. The keystore
   file parser caps its line count. A maliciously-crafted envelope, keystore line, or oversized
   length prefix cannot trigger huge allocations or out-of-bounds reads.
   *(A3 defended at the parse layer; tested in `HostileInputTests`.)*

7. **Domain-separated key derivation.** The HKDF info parameter pins both the algorithm names
   and the wire-format version. A future change of KEM algorithm or hybrid combiner produces a
   different derived key for otherwise-identical inputs. Cross-protocol confusion attacks are
   prevented by construction.
   *(Out-of-scope attacker; tested in `HybridCombinerTests`.)*

8. **Provider-bounded routing.** The envelope records the PQ `publicKeyId` of the keypair it was
   encrypted to. Decryption against the wrong keypair fails fast with a clear
   `KeyNotFoundException` rather than a silent GCM failure.
   *(A3 / operator-error defended; tested in `KeyRotationTests`.)*

9. **Safe diagnostic output.** Every record carrying byte arrays redacts byte content from
   `ToString()` as `<NN bytes>`. Log lines that include these records cannot leak ciphertext or
   the classical wrapped-key token.
   *(Operator hygiene; tested in `ToStringSafetyTests`.)*

10. **Atomic keystore writes.** `FilePostQuantumKeyStore` writes via temp file + `File.Replace`
    with a bounded retry on Windows-specific `IOException` from concurrent readers. A crash
    mid-rotation leaves either the old or the new keystore on disk, never a torn write.
    *(Operational integrity; tested in `FilePostQuantumKeyStoreTests`.)*

## Out of scope

- **Cross-party PQ key exchange** (TLS hybrid groups, IKE PQ, Noise hybrid handshakes). This
  library wraps keys at rest; it does not negotiate session keys between parties.
- **FIPS 140-3 boundary.** The library uses the standard BouncyCastle build, not the BC FIPS
  module. See [KNOWN-GAPS.md §3](../KNOWN-GAPS.md#3-not-fips-140-validated).
- **Process memory protection.** No managed-runtime library can defend the keys it currently
  holds against an attacker reading the process's address space.
- **Replay protection on wrapped keys.** Data Protection itself owns key activation/expiration
  windows. The envelope is opaque to that policy; if you can replay a stale Data Protection key,
  the wrap is irrelevant.

---

*To God be the glory — 1 Corinthians 10:31.*
