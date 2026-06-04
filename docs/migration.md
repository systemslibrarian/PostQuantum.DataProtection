# Migration guide

How to swap in `PostQuantum.DataProtection` on a host that already protects its Data Protection
keys with something else. The goal is **no user-visible disruption** — existing cookies,
antiforgery tokens, and DP-protected payloads should keep working through the switch.

Status as of **`0.1.0-preview.4`**.

## The principle

ASP.NET Core Data Protection stores its keys with two pieces of metadata that matter here:

```xml
<encryptedSecret decryptorType="…">
  <…encrypted payload…/>
</encryptedSecret>
```

The `decryptorType` attribute names the type that will be used to unwrap the key at load time.
Data Protection looks at that attribute *per key file*, not per host. That means **a single
key directory can contain keys protected by different encryptors at the same time**, and each
key gets decrypted by the type its file names.

So the migration path is:

1. **Keep both decryptors registered** for a transition window.
2. **Point the encryptor at PQ** so fresh keys use the new wrap.
3. **Let old keys expire naturally** under the old wrap.
4. **Remove the old decryptor** once no in-use key file names it any more.

You never re-encrypt existing keys. They roll off as DP rotates.

## From `ProtectKeysWithDpapi*` (Windows DPAPI)

Common in older intranet/Windows-host deployments. The old encryptor is
`DpapiXmlEncryptor`/`DpapiNGXmlEncryptor`; the decryptor type recorded on existing keys is
`Microsoft.AspNetCore.DataProtection.XmlEncryption.DpapiXmlDecryptor` (or `DpapiNG`).

```csharp
// Before
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys"))
    .ProtectKeysWithDpapiNG();
```

```csharp
// After — fresh keys get the PQ wrap. Old DPAPI-wrapped keys keep decrypting because
// DpapiNGXmlDecryptor is still on the host (it's a built-in type registered automatically;
// no code change required for the decryptor side).
builder.Services.AddPostQuantumKeyManagement(o => { o.Passphrase = builder.Configuration["..."]!; });
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys"))
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/pq-keystore.txt";
        o.Mode = HybridKemMode.Hybrid;
    });
```

Existing DPAPI-encrypted keys still unwrap because Data Protection's `IActivator` can construct
the DPAPI decryptor on its own — it's part of `Microsoft.AspNetCore.DataProtection`. New keys are
wrapped by PQ. Once the DPAPI-wrapped keys expire (90 days by default), the transition is
complete.

> ⚠️ DPAPI-encrypted keys are bound to the host's user/machine. If your migration also moves the
> host (e.g. to Linux), you cannot decrypt them. Roll keys over before migrating, or accept the
> forced sign-out.

## From `ProtectKeysWithAzureKeyVault`

```csharp
// Before
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(...)
    .ProtectKeysWithAzureKeyVault(new Uri("https://kv.vault.azure.net/keys/dp-key/..."), new DefaultAzureCredential());
```

```csharp
// After
builder.Services.AddPostQuantumKeyManagement(o => { o.Passphrase = builder.Configuration["..."]!; });
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(...)
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/unused.txt";   // ignored when AKV store is registered
        o.Mode = HybridKemMode.Hybrid;
    });
builder.Services.AddPostQuantumDataProtectionAzureKeyVault(new Uri("https://kv.vault.azure.net/"));
```

The Azure Key Vault decryptor type
(`Microsoft.AspNetCore.DataProtection.AzureKeyVault.AzureKeyVaultXmlDecryptor`) stays in the
service container as long as you keep referencing the
`Azure.Extensions.AspNetCore.DataProtection.Keys` package — you do **not** have to call
`.ProtectKeysWithAzureKeyVault()` to keep old keys decrypting. Drop the call; keep the package.

> ⚠️ The two systems use Azure Key Vault for different things. The old call uses an *AKV
> cryptographic key* to wrap DP keys. The new `AddPostQuantumDataProtectionAzureKeyVault` uses
> *AKV Secrets* to persist PQ keypairs. You can have both at once; they don't conflict.

## From `ProtectKeysWithCertificate`

```csharp
// Before
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys"))
    .ProtectKeysWithCertificate(myCert);
```

```csharp
// After — fresh keys move to PQ. Old certificate-wrapped keys keep decrypting as long as the
// certificate is still loaded.
builder.Services.AddPostQuantumKeyManagement(o => { o.Passphrase = builder.Configuration["..."]!; });
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("keys"))
    .UnprotectKeysWithAnyCertificate(myCert)   // ← keep the cert available for decryption of legacy keys
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/pq-keystore.txt";
        o.Mode = HybridKemMode.Hybrid;
    });
```

`UnprotectKeysWithAnyCertificate` registers the certificate as available for decryption without
making it the active encryptor. Old keys roll off naturally.

## Verifying the transition

After deploying the migrated host:

1. **Check the on-disk shape.**
   ```bash
   ls keys/data-protection/
   pq-dp inspect keys/data-protection/key-*.xml | grep "Public key id"
   ```
   Some files will have `<pqEnvelope>` elements; others will retain their old wrappers. That is
   correct.

2. **Hit a real DP-protected endpoint twice.** First call mints a fresh key (PQ-wrapped); second
   call rolls forward. Both should succeed.

3. **Watch the metrics.** `pq_dataprotection.encryptions` should tick up on fresh-key creation;
   `pq_dataprotection.decryptions` should remain quiet (the in-memory key ring caches the
   unwrapped keys).

## When the transition is complete

After all keys created before the migration have expired (default DP lifetime is 90 days), you
can drop the legacy decryptor:

- DPAPI: nothing to drop. The decryptor lives inside `Microsoft.AspNetCore.DataProtection` and
  has no cost when not invoked.
- Azure Key Vault key (cryptographic key, not secret): you can stop loading
  `Azure.Extensions.AspNetCore.DataProtection.Keys` if you want.
- Certificate: drop `UnprotectKeysWithAnyCertificate(...)`.

## What you cannot migrate without re-issuing

- Data Protection keys wrapped under a key that has been deleted or revoked.
- Keys whose encryptor's decryptor type is no longer registered.
- Keys whose wrapping key is on a different host (DPAPI, machine-bound HSM) than the new host.

In those cases, the user-visible effect is a forced sign-out / token refresh. The PQ encryptor
cannot recover keys whose wrapping was never PQ-encrypted in the first place; it can only ensure
that *fresh* keys are PQ-wrapped going forward.

---

*To God be the glory — 1 Corinthians 10:31.*
