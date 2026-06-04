# WorkerService.Sample

A .NET Worker Service that uses `PostQuantum.DataProtection` outside ASP.NET Core. Demonstrates:

- One-line PQ Data Protection wiring (`AddDataProtection().ProtectKeysWithPostQuantum(...)`) in a
  non-web host.
- **Scheduled PQ keypair rotation** via `PostQuantumDataProtectionOptions.RotationInterval` —
  watch the `PqKeyManagerRotated` log line tick every 30 s.
- The library's structured logging: encrypt/decrypt events, rotation events, load events.

## Run

```bash
cd samples/WorkerService.Sample
rm -rf keys/
dotnet run
```

You'll see something like:

```
info: PostQuantum.DataProtection.Keys.PostQuantumKeyManager[11]
      PQ keystore is empty — generating the inaugural ML-KEM-768 keypair.
info: WorkerService.Sample.TokenIssuingWorker[0]
      Worker started; will issue a PQ-protected job token every 5s. Press Ctrl+C to stop.
info: WorkerService.Sample.TokenIssuingWorker[0]
      Issued PQ-protected job token: payload=job-00001-at-..., tokenChars=276, roundtripOk=True
...
info: PostQuantum.DataProtection.Hosting.PostQuantumRotationHostedService[22]
      Scheduled PQ keypair rotation completed; new active key 'pq-mlkem768-...'.
```

## Inspect

```bash
ls keys/data-protection/
ls -la keys/pq-keystore.txt    # grows by ~5 KiB each rotation
dotnet tool install --global PostQuantum.DataProtection.Cli --prerelease
pq-dp inspect keys/data-protection/key-*.xml | head -20
```

---

*To God be the glory — 1 Corinthians 10:31.*
