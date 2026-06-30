# Cryptographic specification (frozen for 1.0)

This document specifies, precisely enough to audit, every cryptographic construction
`PostQuantum.DataProtection` performs. It is the stable target for an external cryptographic
review. The wire format and the derivations described here are **frozen as of `1.0.0`**; any
change after 1.0 goes through a format-version bump (see [§7](#7-versioning)).

The authoritative implementation is in:

- `src/PostQuantum.DataProtection/Hybrid/HybridKemEnvelope.cs` — envelope encode/decode
- `src/PostQuantum.DataProtection/Hybrid/HybridCombiner.cs` — key derivation
- `src/PostQuantum.DataProtection/Hybrid/MlKem*.cs` — ML-KEM (FIPS 203) wrapper
- `src/PostQuantum.DataProtection/Keys/PostQuantumKeyManager.cs` — secret-key wrapping
- `src/PostQuantum.DataProtection/Keys/PostQuantumKeyPair.cs` — keypair token

Known-answer tests for the derivations are in
`tests/PostQuantum.DataProtection.Tests/CombinerKnownAnswerTests.cs`; FIPS 203 conformance KATs are
in the `AcvpKat*` tests. The decoder is the source of truth — every length-prefixed field is capped
at 1 MiB (`PortableEncoding.MaxFieldLength`) with overflow-safe bounds arithmetic.

---

## 1. Primitives

| Primitive | Source | Notes |
|---|---|---|
| ML-KEM-512 / 768 / 1024 | BouncyCastle (`net8.0`/`net9.0`), `System.Security.Cryptography.MLKem` (`net10.0+`) | FIPS 203. Both backends produce byte-identical outputs (cross-checked by KAT). Shared secret is 32 bytes. |
| AES-256-GCM | `System.Security.Cryptography.AesGcm` | 96-bit nonce, 128-bit tag. |
| HKDF-SHA-256 | `System.Security.Cryptography.HKDF` | Used by the `MlKemOnly` and `Hybrid` combiners. |
| SHA3-256 | `System.Security.Cryptography.SHA3_256` | Used by the `XWingHybrid` combiner. |
| CSPRNG | `System.Security.Cryptography.RandomNumberGenerator` | All nonces. |

We do not implement primitives ([KNOWN-GAPS.md §B4](../KNOWN-GAPS.md)).

## 2. Envelope wire format (version 1)

Each protected Data Protection XML element carries one Base64Url-encoded binary blob. All
length prefixes are 4-byte big-endian. Byte order top to bottom:

```
[FormatVersion : byte = 1]
[Mode          : byte]                  // 0 = MlKemOnly, 1 = Hybrid, 2 = XWingHybrid
[KemAlgorithm  : len-prefixed utf8]     // "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024"
[PublicKeyId   : len-prefixed utf8]     // id of the keypair this was encrypted to
[KemCiphertext : len-prefixed bytes]    // ML-KEM encapsulation (768/1088/1568 bytes)
[ClassicalWrap : len-prefixed utf8]     // WrappedContentKey token; EMPTY iff Mode = MlKemOnly
[Nonce         : 12 raw bytes]          // AES-GCM nonce (also the HKDF salt / X-Wing salt)
[Tag           : 16 raw bytes]          // AES-GCM tag
[Ciphertext    : len-prefixed bytes]    // AES-256-GCM ciphertext of the original XML payload
```

Decode rejects, with `FormatException` (and `TryDecode` returns false): an unknown
`FormatVersion`, a `Mode` byte > 2, a `Hybrid`/`XWingHybrid` envelope with an empty classical token,
an `MlKemOnly` envelope carrying a classical token, and any trailing bytes after the ciphertext. The
XML carries advisory `version`/`mode`/`publicKeyId` attributes, but the encoded blob is the source of
truth and is re-validated on decode.

## 3. Content-key derivation (combiners)

Let `ss_pq` be the 32-byte ML-KEM shared secret, `ss_c` the classical shared secret (the raw bytes
of a fresh `IContentKeyProvider` content key), `ct_pq` the ML-KEM ciphertext, and `salt` the 12-byte
envelope nonce. All three modes output a 32-byte AES-256 key. The domain-separation labels are
frozen ASCII:

```
L_mlkemonly = "PostQuantum.DataProtection v1 ML-KEM-768 + AES-256-GCM"
L_hybrid    = "PostQuantum.DataProtection v1 hybrid ML-KEM-768 + AES-256-GCM"
L_xwing     = "PostQuantum.DataProtection v1 XWing-hybrid ML-KEM-768 + AES-256-GCM"
```

**MlKemOnly** (mode 0):
```
key = HKDF-SHA256(ikm = ss_pq, salt = salt, info = L_mlkemonly, L = 32)
```

**Hybrid** (mode 1):
```
key = HKDF-SHA256(ikm = ss_pq || ss_c, salt = salt, info = L_hybrid, L = 32)
```

**XWingHybrid** (mode 2, the default):
```
key = SHA3-256( L_xwing || ss_pq || ss_c || ct_pq || salt )
```

`XWingHybrid` is the recommended default: it binds the ML-KEM ciphertext `ct_pq` into the
derivation, matching the security argument of
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
(adapted: the "classical" secret here is the host KEK content key, not a classical KEM). `Hybrid`
does not bind the ciphertext but remains supported. In all hybrid modes an attacker must defeat
**both** the ML-KEM layer and the classical KEK layer to recover the content key. All intermediate
secret buffers are zeroed after use (`CryptographicOperations.ZeroMemory`).

A fresh `salt` (nonce) is drawn per envelope, so even with a fixed keypair and a fixed KEK every
payload gets a unique content key. The 12-byte nonce serves double duty as the AES-GCM nonce and the
KDF salt; because it is unique per envelope this is safe, and `XWingHybrid` additionally folds it
into the hash.

## 4. Payload encryption

```
ciphertext, tag = AES-256-GCM(key, nonce, plaintext = utf8(element), aad = none)
```
The original XML element is serialized with `SaveOptions.DisableFormatting`. No associated data is
used; integrity of the routing fields is provided by their being inputs to (Hybrid/XWing) or
implied by (the decapsulation that produces `ss_pq`) the content-key derivation, plus the AEAD tag
over the payload.

## 5. Long-lived secret-key wrapping

The ML-KEM private key never touches disk in plaintext. `PostQuantumKeyManager` wraps it with a
fresh content key (DEK) minted from the host `IContentKeyProvider` and stores this opaque blob:

```
[InnerWrappedDekToken : len-prefixed utf8]  // WrappedContentKey.Encode() from the host provider
[Nonce                : 12 raw bytes]
[Tag                  : 16 raw bytes]
[SkCiphertext         : len-prefixed bytes] // AES-256-GCM(DEK, nonce, sk)
```

On decapsulate the manager decodes the inner token, unwraps the DEK via `IContentKeyProvider`,
AES-GCM-decrypts the SK, performs ML-KEM decapsulation, and zeroes the plaintext SK in a `finally`.
A tag mismatch (wrong KEK, corrupted blob) throws `CryptographicException` — fail closed.

## 6. Keypair token and key id

The persisted keypair token (`PostQuantumKeyPair`, format version 1):

```
[FormatVersion : byte = 1]
[KeyId         : len-prefixed utf8]
[Algorithm     : len-prefixed utf8]
[PublicKey     : len-prefixed bytes]
[WrappedSecret : len-prefixed bytes]   // the §5 blob, opaque
[CreatedAtUtc  : int64 big-endian]     // Unix milliseconds
```

The key id is a stable function of the public key:
```
KeyId = prefix(parameterSet) + lowerhex( SHA-256(publicKey)[0..6] )
       where prefix ∈ { "pq-mlkem512-", "pq-mlkem768-", "pq-mlkem1024-" }
```
The 6-byte (48-bit) truncation is a routing identifier, not a security boundary; collision is
cryptographically negligible at realistic keypair counts.

## 7. Versioning

`HybridKemEnvelope.CurrentFormatVersion` and the keypair token version are both `1` and frozen for
1.0. A decoder rejects any other version rather than guessing. Post-1.0, a format change bumps the
version, keeps `Decode` able to read prior versions where feasible, and is called out in
`CHANGELOG.md`. See [KNOWN-GAPS.md §D3](../KNOWN-GAPS.md).

## 8. Security properties (claims to audit)

1. **Hybrid confidentiality.** Recovering a content key requires both `ss_pq` (ML-KEM) and `ss_c`
   (host KEK) in `Hybrid`/`XWingHybrid`. Breaking one layer preserves confidentiality.
2. **Harvest-now-decrypt-later resistance.** A passive adversary recording envelopes today cannot
   decrypt them with a future CRQC without also breaking the classical KEK.
3. **Ciphertext binding (XWingHybrid).** Altering `ct_pq` changes the derived key (KAT-asserted).
4. **Domain separation.** The three modes derive distinct keys from identical secrets (KAT-asserted).
5. **No plaintext SK at rest.** The private key exists in plaintext only transiently in memory and is
   zeroed after use.
6. **Fail-closed.** Wrong KEK, unknown key id, tampered envelope, or malformed input all raise rather
   than degrade.
7. **Hostile-input resistance.** All length-prefixed fields are bounded; malformed input cannot force
   large allocations or out-of-bounds reads.

See [docs/threat-model.md](threat-model.md) for the attacker model these properties answer.

---

*To God be the glory — 1 Corinthians 10:31.*
