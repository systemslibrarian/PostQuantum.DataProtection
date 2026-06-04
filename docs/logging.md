# Logging reference

Every log line `PostQuantum.DataProtection` emits has a stable EventId. This page is the
authoritative list — wire your log analyser, alert rules, and dashboards against these.

The EventIds are **stable across patch versions** within a major version. Adding new events
bumps the next free EventId; renumbering existing events is a breaking change reserved for
major versions.

Status as of **`0.1.0-preview.6`**.

## Categories

The library uses three `ILogger<T>` categories:

| Category | What logs there |
|---|---|
| `PostQuantum.DataProtection.PostQuantumXmlEncryptor` | Encryption events (1) |
| `PostQuantum.DataProtection.PostQuantumXmlDecryptor` | Decryption events (2–4) |
| `PostQuantum.DataProtection.Keys.PostQuantumKeyManager` | Key load / first-run / rotation (10–12) |
| `PostQuantum.DataProtection.Hosting.PostQuantumRotationHostedService` | Scheduled rotation (20–23) |

## Event reference

| EventId | Name | Level | Category | Message template |
|---:|---|---|---|---|
| 1 | `PqDataProtectionEncrypted` | Debug | XmlEncryptor | Encrypted Data Protection element (mode={Mode}, publicKeyId={PublicKeyId}, ciphertextBytes={CiphertextLength}). |
| 2 | `PqDataProtectionDecrypted` | Debug | XmlDecryptor | Decrypted Data Protection element (mode={Mode}, publicKeyId={PublicKeyId}). |
| 3 | `PqDataProtectionUnknownKeypair` | Error | XmlDecryptor | Failed to decrypt: envelope was wrapped under PQ keypair '{PublicKeyId}', which is not loaded. Check the keystore path and restore from backup if necessary. |
| 4 | `PqDataProtectionAuthFailed` | Error | XmlDecryptor | Failed to decrypt: AES-GCM authentication failed for envelope wrapped under PQ keypair '{PublicKeyId}'. The envelope was tampered with, or the host KEK is wrong. |
| 10 | `PqKeyManagerLoaded` | Information | PostQuantumKeyManager | Loaded {Count} PQ keypair(s) from store; active key is '{ActiveKeyId}'. |
| 11 | `PqKeyManagerFirstRun` | Information | PostQuantumKeyManager | PQ keystore is empty — generating the inaugural ML-KEM-768 keypair. |
| 12 | `PqKeyManagerRotated` | Information | PostQuantumKeyManager | Generated new active PQ keypair '{KeyId}'. Old keypairs remain loaded and continue to decrypt previously-wrapped Data Protection keys. |
| 20 | `PqRotationDisabled` | Debug | PostQuantumRotationHostedService | Scheduled PQ keypair rotation is disabled (RotationInterval = TimeSpan.Zero). |
| 21 | `PqRotationStarted` | Information | PostQuantumRotationHostedService | Scheduled PQ keypair rotation enabled; first rotation in {Interval}. |
| 22 | `PqRotationCompleted` | Information | PostQuantumRotationHostedService | Scheduled PQ keypair rotation completed; new active key '{KeyId}'. |
| 23 | `PqRotationFailed` | Error | PostQuantumRotationHostedService | Scheduled PQ keypair rotation failed; the host is still alive and will retry in {Interval}. |

## Alert / dashboard guidance

| Signal | Trigger | Severity | Why |
|---|---|---|---|
| `PqDataProtectionUnknownKeypair` (EventId 3) | any | **page** | An envelope references a keypair not in the store. Either the keystore was rebuilt or the host points at the wrong path. |
| `PqDataProtectionAuthFailed` (EventId 4) | any | **page** | Tampered envelope, wrong host KEK, or a corrupted keystore. Either way: investigate immediately. |
| `PqRotationFailed` (EventId 23) | any | **page** | Scheduled rotation failed. The host stays alive but the active keypair is not advancing. |
| `PqKeyManagerFirstRun` (EventId 11) | any after first deploy | warn | A first-run event after the host has been deployed should not normally fire. If it does, the keystore was lost. |
| `PqKeyManagerLoaded` (EventId 10) | absent at startup | warn | The host should always emit this on boot. Absent = the boot path didn't reach `PostQuantumKeyManager`. |
| `PqRotationCompleted` (EventId 22) | absent at the configured interval | warn | If you set `RotationInterval = 90 days`, an entry should fire every ~90 days. |

## Sample structured output (JSON via Microsoft.Extensions.Logging)

```jsonc
{
  "Timestamp": "2026-06-04T14:32:01.123Z",
  "Level": "Information",
  "Category": "PostQuantum.DataProtection.Keys.PostQuantumKeyManager",
  "EventId": 10,
  "EventName": "PqKeyManagerLoaded",
  "Message": "Loaded 3 PQ keypair(s) from store; active key is 'pq-mlkem768-4411e03446f5'.",
  "Properties": {
    "Count": 3,
    "ActiveKeyId": "pq-mlkem768-4411e03446f5"
  }
}
```

```jsonc
{
  "Timestamp": "2026-06-04T14:35:17.880Z",
  "Level": "Error",
  "Category": "PostQuantum.DataProtection.PostQuantumXmlDecryptor",
  "EventId": 4,
  "EventName": "PqDataProtectionAuthFailed",
  "Exception": "System.Security.Cryptography.AuthenticationTagMismatchException: …",
  "Properties": {
    "PublicKeyId": "pq-mlkem768-4411e03446f5"
  }
}
```

## Filtering by category

The standard ASP.NET Core / `Microsoft.Extensions.Logging` config snippet:

```jsonc
// appsettings.json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "PostQuantum.DataProtection": "Information",
      "PostQuantum.DataProtection.PostQuantumXmlEncryptor": "Warning",
      "PostQuantum.DataProtection.PostQuantumXmlDecryptor": "Warning"
    }
  }
}
```

In production this typically silences the per-envelope `Debug` events (1 and 2) while keeping
the lifecycle events (10–12, 20–23) at `Information` and the failure events (3, 4, 23) at
`Error`. The `Meter` and `ActivitySource` named `PostQuantum.DataProtection` carry the
quantitative signal regardless — see [`docs/deployment.md`](deployment.md) §6 for the metrics
table.

## Versioning policy

- EventIds **never change number** within a major version.
- EventIds **may be added** in minor versions; new ones take the next free number.
- EventIds **may be retired** only in a major version, and the retired number is not reused.

---

*To God be the glory — 1 Corinthians 10:31.*
