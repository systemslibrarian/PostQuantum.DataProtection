# Wire format

This is the precise statement of what `PostQuantum.DataProtection` writes to disk. Every binary
choice is here; if the implementation drifts from this document, the document is the bug.

Status as of **`0.1.0-preview.1`**. Two layouts are versioned and documented below:

1. [`HybridKemEnvelope`](#1-hybridkemenvelope) — the per-Data-Protection-key envelope embedded
   inside the `<pqEnvelope>` XML element ASP.NET Core writes under
   `<descriptor>/<descriptor>/<encryptedSecret>`.
2. [`PostQuantumKeyPair`](#2-postquantumkeypair) — the long-lived ML-KEM keypair token persisted
   in `keys/pq-keystore.txt`.

## Conventions

- All integers are **big-endian**.
- All byte fields are 4-byte length-prefixed unless explicitly marked **raw**.
- All strings are UTF-8 byte fields, length-prefixed.
- Every length prefix is capped at **1 MiB** by the decoder. The keystore file parser also caps
  the number of lines (1 000).
- All encoded tokens are wrapped in **Base64Url** (no padding) before they touch disk or XML.

## 1. `HybridKemEnvelope`

Wire-format version: **1**.

```
[FormatVersion : byte = 1]
[Mode          : byte]                     // 0 = MlKemOnly, 1 = Hybrid
[KemAlgorithm  : length-prefixed utf8]     // currently always "ML-KEM-768"
[PublicKeyId   : length-prefixed utf8]     // the id of the long-lived PQ keypair this is encrypted to
[KemCiphertext : length-prefixed bytes]    // ML-KEM-768 encapsulation output (1088 bytes)
[ClassicalWrap : length-prefixed utf8]     // a WrappedContentKey.Encode() token; empty string in MlKemOnly
[Nonce         : 12 raw bytes]             // AES-GCM nonce
[Tag           : 16 raw bytes]             // AES-GCM authentication tag
[Ciphertext    : length-prefixed bytes]    // AES-256-GCM ciphertext of the original XML payload
```

### XML wrapper

The Base64Url-encoded envelope sits inside a single XML element whose `xmlns` is pinned and
whose attributes are diagnostic mirrors of the encoded routing fields:

```xml
<pqEnvelope xmlns="https://schemas.systemslibrarian.dev/pq-dataprotection/2026/01"
            version="1"
            mode="Hybrid"
            publicKeyId="pq-mlkem768-a3c7e2b9">
  BASE64URL-of-the-encoded-envelope
</pqEnvelope>
```

The XML attributes are advisory and visible to logs / tooling; **the decoder treats the encoded
envelope as the source of truth** and re-checks any cross-references so a tampered attribute set
cannot fool a downstream reader.

### Key derivation

Mode `MlKemOnly`:

```
DerivedKey = HKDF-SHA-256(
    salt = Nonce,
    ikm  = ML-KEM shared secret (32 bytes),
    info = "PostQuantum.DataProtection v1 ML-KEM-768 + AES-256-GCM",
    L    = 32 bytes
)
```

Mode `Hybrid`:

```
DerivedKey = HKDF-SHA-256(
    salt = Nonce,
    ikm  = ML-KEM shared secret (32 bytes) || classical DEK secret (32 bytes),
    info = "PostQuantum.DataProtection v1 hybrid ML-KEM-768 + AES-256-GCM",
    L    = 32 bytes
)
```

The `info` field domain-separates the two modes and pins the wire-format version. A future change
of KEM algorithm or hybrid combiner produces a different derived key for otherwise-identical
inputs — cross-protocol confusion attacks are prevented by construction.

The `salt` field is the per-envelope 96-bit AES-GCM nonce. Reuse of the same KEM keypair across
many encryptions therefore still produces a fresh derived key per envelope, because the salt is
fresh per envelope.

### Sizes

| Field            | Bytes (Hybrid mode, AES-256-GCM, ML-KEM-768)                           |
| ---------------- | ---------------------------------------------------------------------- |
| FormatVersion    | 1                                                                      |
| Mode             | 1                                                                      |
| KemAlgorithm     | 4 + len("ML-KEM-768") = 4 + 10 = 14                                    |
| PublicKeyId      | 4 + ≈20 (the `pq-mlkem768-<6 hex>` form is 18 chars)                   |
| KemCiphertext    | 4 + 1088 = 1092                                                        |
| ClassicalWrap    | 4 + ≈200 (varies; a WrappedContentKey.Encode() token of the local provider) |
| Nonce            | 12 (raw)                                                               |
| Tag              | 16 (raw)                                                               |
| Ciphertext       | 4 + (DP key XML byte length, typically 100–400 bytes)                  |
| **Total**        | **≈ 1.5 KiB per Data Protection key**                                  |

After Base64Url expansion (4/3) and the surrounding XML, expect ≈ 2 KiB per persisted Data
Protection key. Modern Data Protection deployments hold a handful to a few dozen keys at any one
time; the on-disk overhead is bounded and small.

## 2. `PostQuantumKeyPair`

Wire-format version: **1**.

The keystore file holds one keypair per line:

```
active <keyId>
pair   <base64url token>
pair   <base64url token>
...
```

Each `pair` token decodes to:

```
[FormatVersion : byte = 1]
[KeyId         : length-prefixed utf8]   // "pq-mlkem768-" + hex(SHA-256(pk)[..6])
[Algorithm     : length-prefixed utf8]   // currently always "ML-KEM-768"
[PublicKey     : length-prefixed bytes]  // ML-KEM-768 public key (1184 bytes)
[WrappedSecret : length-prefixed bytes]  // opaque blob; see below
[CreatedAtUtc  : 8 raw bytes (big-endian int64)]   // Unix milliseconds
```

The `WrappedSecret` blob is itself versioned by the implementation and follows the layout:

```
[InnerWrappedDekToken : length-prefixed utf8]   // a WrappedContentKey.Encode() from the host provider
[Nonce                : 12 raw bytes]            // AES-GCM nonce
[Tag                  : 16 raw bytes]            // AES-GCM tag
[SkCiphertext         : length-prefixed bytes]   // AES-256-GCM of the ML-KEM private key (2400 bytes)
```

### Why the inner-DEK indirection

`PostQuantum.KeyManagement.IContentKeyProvider` wraps 32-byte content keys (DEKs). The ML-KEM
private key is 2 400 bytes. The standard envelope-encryption move is to mint a fresh DEK, AES-GCM
the SK with that DEK, and persist (wrapped DEK || nonce || tag || ciphertext) as one opaque blob.
That is what the `WrappedSecret` layout above does.

### Sizes

| Field          | Bytes                                                                  |
| -------------- | ---------------------------------------------------------------------- |
| FormatVersion  | 1                                                                      |
| KeyId          | 4 + 18 ≈ 22                                                            |
| Algorithm      | 4 + 10 = 14                                                            |
| PublicKey      | 4 + 1184 = 1188                                                        |
| WrappedSecret  | 4 + (inner DEK token ≈ 200) + 12 + 16 + 4 + 2400 ≈ 2636                |
| CreatedAtUtc   | 8                                                                      |
| **Total**      | **≈ 3.9 KiB per keypair**                                              |

After Base64Url expansion, a fresh `pq-keystore.txt` after first-run holds one line of ≈ 5.2 KiB
plus the leading `active <keyId>` line. Each rotation adds another ≈ 5.2 KiB line.

## Versioning policy

- The decoder rejects unknown `FormatVersion` values with a clear `FormatException`.
- Whenever the wire layout changes:
  - The version byte is incremented.
  - `Decode` learns the new layout and continues to read prior versions where feasible (the
    keystore is permanent — losing the ability to read v1 means losing every keypair).
  - `PackageReleaseNotes` and `CHANGELOG.md` name the change.
- Pre-`1.0`, breaking format changes are allowed if they fix a real problem. Post-`1.0`, the
  policy is: SemVer applies to the wire format too.

---

*To God be the glory — 1 Corinthians 10:31.*
