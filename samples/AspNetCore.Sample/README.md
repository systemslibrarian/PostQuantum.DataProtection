# AspNetCore.Sample

A minimal-API ASP.NET Core host that protects cookies and antiforgery tokens with
`PostQuantum.DataProtection`'s ML-KEM-768 + AES-256-GCM hybrid envelope.

## What it shows

- One-line wiring of `PostQuantum.KeyManagement` (the classical KEK) and
  `PostQuantum.DataProtection` (the post-quantum / hybrid Data Protection wrap).
- A real **cookie authentication** roundtrip whose underlying signing key is persisted under a
  `<pqEnvelope>` element.
- A real **antiforgery-token** roundtrip — same protection chain.
- A direct `IDataProtector.Protect` / `Unprotect` endpoint at `/protect-demo` for arbitrary payloads.
- A `POST /rotate-pq` endpoint that rotates the active ML-KEM-768 keypair. Old payloads continue to
  decrypt because the old keypair stays in the keystore.

## Run it

```bash
cd samples/AspNetCore.Sample
ASPNETCORE_ENVIRONMENT=Development dotnet run
```

Open the printed URL. Sign in. Inspect:

```text
keys/host-keyring.bin             # PostQuantum.KeyManagement KEK ring
keys/pq-keystore.txt              # ML-KEM-768 keypair (SK wrapped by the host KEK)
keys/data-protection/key-*.xml    # Data Protection keys — each <encryptedSecret> is a <pqEnvelope>
```

Every `key-*.xml` file contains the same shape:

```xml
<encryptedSecret decryptorType="PostQuantum.DataProtection.PostQuantumXmlDecryptor, PostQuantum.DataProtection">
  <pqEnvelope xmlns="https://schemas.systemslibrarian.dev/pq-dataprotection/2026/01"
              version="1" mode="Hybrid" publicKeyId="pq-mlkem768-...">
    BASE64URL...
  </pqEnvelope>
</encryptedSecret>
```

## What is *not* shown

- A production secret store for the host passphrase. The sample reads it from
  `appsettings.Development.json`; in production the only correct answer is Azure Key Vault, AWS
  Secrets Manager, environment-variable-from-a-vault, etc.
- Distributed Data Protection key persistence (Redis, Azure Blob, etc.). The sample uses local
  files. The wrap is the same regardless of the persistence target.
- Authorization beyond a single signed-in identity. The sample's `/rotate-pq` endpoint is open
  for demonstration; gate it behind admin-only authorization in real apps.

## Tear-down

```bash
rm -rf keys/
```

---

*To God be the glory — 1 Corinthians 10:31.*
