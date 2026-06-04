# API reference

Generated from the XML documentation in every public type the library exposes. Browse from the
TOC on the left.

The PQ data-protection family ships five packages:

| Package | What it provides |
|---|---|
| `PostQuantum.DataProtection` | Core: encryptor / decryptor, key manager, file-backed key store, DI extensions, health check, hosted rotation service, metrics. |
| `PostQuantum.DataProtection.AzureKeyVault` | Azure Key Vault-backed `IPostQuantumKeyStore`. |
| `PostQuantum.DataProtection.Aws` | AWS Secrets Manager-backed `IPostQuantumKeyStore`. |
| `PostQuantum.DataProtection.Testing` | In-memory `FakePostQuantumKeyStore` for consumer unit tests. |
| `PostQuantum.DataProtection.OpenTelemetry` | One-line OTel wiring for the built-in Meter and ActivitySource. |

Companion CLI:

| Tool | What it does |
|---|---|
| `PostQuantum.DataProtection.Cli` (`pq-dp`) | Inspect persisted Data Protection key XML files. No secrets emitted. |

---

*To God be the glory — 1 Corinthians 10:31.*
