# pq-dp — diagnostics CLI for PostQuantum.DataProtection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

A tiny `dotnet tool` that inspects PostQuantum.DataProtection envelope XML files on disk.

> ⚠️ **Preview (`0.1.0-preview.4`).** Tracks the core preview cadence.

## Install

```bash
dotnet tool install --global PostQuantum.DataProtection.Cli --prerelease
```

## Use

```bash
pq-dp inspect keys/data-protection/key-c6b3b03f-b73a-477b-92e5-d19ae0e0b5fd.xml
```

Sample output:

```text
File:                keys/data-protection/key-c6b3b03f-b73a-477b-92e5-d19ae0e0b5fd.xml
Format version:      1
Mode:                Hybrid
KEM algorithm:       ML-KEM-768
Public key id:       pq-mlkem768-4411e03446f5
KEM ciphertext:      1088 bytes
Classical wrap:      236 chars
AES-GCM nonce:       12 bytes
AES-GCM tag:         16 bytes
AES-GCM ciphertext:  120 bytes
```

No secrets are printed. The CLI reads only the envelope's routing metadata.

## What it can't do (yet)

- Decrypt anything. The CLI has no host KEK, no ML-KEM secret key, no access to the keystore.
  Decryption stays inside the host process for a reason — see [`docs/threat-model.md`](../../docs/threat-model.md).
- Generate or rotate keys. Use the runtime API (`PostQuantumKeyManager.RotateAsync`) or an admin
  endpoint in your host.

## Uninstall

```bash
dotnet tool uninstall --global PostQuantum.DataProtection.Cli
```

---

*To God be the glory — 1 Corinthians 10:31.*
