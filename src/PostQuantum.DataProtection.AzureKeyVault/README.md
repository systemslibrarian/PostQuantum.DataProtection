# PostQuantum.DataProtection.AzureKeyVault

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

Azure Key Vault-backed `IPostQuantumKeyStore` for
[`PostQuantum.DataProtection`](https://www.nuget.org/packages/PostQuantum.DataProtection). Stores
the long-lived ML-KEM-768 keypairs that wrap ASP.NET Core Data Protection keys in an Azure Key
Vault Secrets vault — durable, audited, shareable across replicas — without ever placing
plaintext on disk.

> ⚠️ **Preview (`0.1.0-preview.3`).** Tracks the core
> [`PostQuantum.DataProtection`](https://github.com/systemslibrarian/PostQuantum.DataProtection)
> preview cadence. API and storage layout may still change before `1.0`.

## Why

The default `FilePostQuantumKeyStore` is single-writer + many-readers on a shared file. That is
fine for single-host deployments; it does not survive serverless, multi-replica containers, or
truly stateless hosts. Azure Key Vault Secrets gives you:

- **Durable, replicated storage** (the vault's own SLA, not your container's).
- **Audit trail** (every read and write logs to the vault's audit pipeline).
- **Shared access** across every replica that runs your service principal / managed identity.
- **No new trust boundary** — the PQ secret key is already wrapped by the host
  `IContentKeyProvider` before it reaches the vault. Key Vault sees an opaque blob.

## Install

```bash
dotnet add package PostQuantum.DataProtection.AzureKeyVault --prerelease
```

## Wire it up

```csharp
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// 1. The classical KEK provider (host KEK that wraps the ML-KEM secret key).
builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("Missing passphrase");
    o.WorkFactor = KekWorkFactor.Moderate;
    o.KeyringPath = "keys/host-keyring.bin"; // or your own IKeyringStore
});

// 2. ASP.NET Core Data Protection with the PQ wrap.
builder.Services
    .AddDataProtection()
    .PersistKeysToAzureBlobStorage(/* ... */)
    .ProtectKeysWithPostQuantum(o =>
    {
        // KeyStorePath is required by the bundled file store but is ignored when we override the
        // IPostQuantumKeyStore below. Pass any placeholder.
        o.KeyStorePath = "keys/unused-pq-keystore.txt";
        o.Mode = HybridKemMode.Hybrid;
    });

// 3. Replace the file store with Azure Key Vault.
builder.Services.AddPostQuantumDataProtectionAzureKeyVault(new Uri("https://my-vault.vault.azure.net/"));

WebApplication app = builder.Build();
```

For full control over credential resolution:

```csharp
builder.Services.AddPostQuantumDataProtectionAzureKeyVault(options =>
{
    options.VaultUri = new Uri("https://my-vault.vault.azure.net/");
    options.Credential = new ManagedIdentityCredential();   // or any TokenCredential
    options.SecretPrefix = "pq-dp-prod";                    // optional: share one vault across rings
});
```

## What goes into the vault

The store creates two kinds of secrets per host:

| Secret name                            | Contents                                      |
| -------------------------------------- | --------------------------------------------- |
| `pq-dataprotection-{keyId}`            | The `PostQuantumKeyPair.Encode()` token       |
| `pq-dataprotection-active`             | The active keypair id                         |

Where `{keyId}` is the `pq-mlkem768-<6 hex>` value the library generates. The keypair token is
non-secret in the sense that it carries no plaintext key material — the secret key is wrapped
under the host KEK. The active pointer is non-secret as well.

Customise the `pq-dataprotection` prefix via
`AzureKeyVaultDataProtectionOptions.SecretPrefix` if you share one vault across multiple PQ
rings.

## Required Key Vault permissions

The credential you supply needs **Get**, **List**, and **Set** permissions on Secrets:

- Access policy: `secret get`, `secret list`, `secret set`.
- RBAC: `Key Vault Secrets Officer` (or a custom role with the three actions above).

The store never deletes or purges secrets. Pruning historical keypairs is a deliberate operator
action — see the retention discussion in
[`KNOWN-GAPS.md` §5](../../KNOWN-GAPS.md#5-pq-keypair-rotation-must-keep-old-keys-readable).

## Cost

- **Startup**: 1 `List` + N `Get` calls, where N is the number of keypairs ever generated.
- **Rotation**: 2 `Set` calls per rotation.
- **Steady state**: zero — the store caches in memory after first load.

At one rotation per quarter and a fleet of 100 replicas, that is on the order of 2 vault writes
per quarter from the rotator, plus 100 × (1 + N) reads per cold start. Well below any Key Vault
throughput limit.

## Testing

The store is built around a narrow `IKeyVaultSecretClient` seam — for your own tests you can
substitute an in-memory fake without standing up a real vault. The unit-test project in this
repo (`tests/PostQuantum.DataProtection.AzureKeyVault.Tests`) does exactly that.

---

*To God be the glory — 1 Corinthians 10:31.*
