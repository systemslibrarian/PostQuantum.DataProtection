# PostQuantum.DataProtection.Testing

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

Test fakes for [`PostQuantum.DataProtection`](https://www.nuget.org/packages/PostQuantum.DataProtection).
Write unit tests against your own code that *consumes* the PQ data-protection chain, without
standing up a real ML-KEM keypair, a real classical KEK, or a real file on disk.

> ⚠️ **Preview (`0.1.0-preview.4`).** Tracks the core
> [`PostQuantum.DataProtection`](https://github.com/systemslibrarian/PostQuantum.DataProtection)
> preview cadence.

## Install

```bash
dotnet add package PostQuantum.DataProtection.Testing --prerelease
```

## Use it

```csharp
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

[Fact]
public void My_service_protects_and_unprotects_round_trips()
{
    var services = new ServiceCollection();
    services.AddPostQuantumDataProtectionTesting();   // ← the one line
    using ServiceProvider sp = services.BuildServiceProvider();

    IDataProtectionProvider dp = sp.GetRequiredService<IDataProtectionProvider>();
    IDataProtector protector = dp.CreateProtector("my.purpose");

    string protectedToken = protector.Protect("hello");
    string roundtripped = protector.Unprotect(protectedToken);

    Assert.Equal("hello", roundtripped);
}
```

`AddPostQuantumDataProtectionTesting()` wires:

- A `LocalContentKeyProvider` with a fixed test passphrase at the smallest Argon2id work factor.
- A `FakePostQuantumKeyStore` (in-memory, no disk I/O).
- A `PostQuantumKeyManager` bound to both.
- `AddDataProtection()` configured with the PQ encryptor in `Hybrid` mode.

The chain generates a fresh ML-KEM-768 keypair on first use, wraps the secret key under the host
KEK, and persists everything in memory only. Tests are isolated from each other because the
service provider scopes the fakes.

## When NOT to use this

- **End-to-end tests of the PQ chain itself.** The core repo's
  `tests/PostQuantum.DataProtection.Tests` already does that; you don't need to.
- **Tests that pin file-format compatibility.** Use `FilePostQuantumKeyStore` against a temp
  directory instead.
- **Tests that hit a real cloud Key Vault.** Use the real
  `PostQuantum.DataProtection.AzureKeyVault` store against a test vault.

The fakes here are for *your* tests, against *your* code that *consumes* the abstraction. They are
deliberately tiny and stateless.

---

*To God be the glory — 1 Corinthians 10:31.*
