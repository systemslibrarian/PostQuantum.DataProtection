# Blazor.Sample

A Blazor Server host whose Data Protection keys — the keys that sign the circuit reconnect
token, the auth cookie, and any `IDataProtector` payload — are wrapped under
`PostQuantum.DataProtection`.

## Why this matters

Blazor Server depends on Data Protection for **circuit security**. The interactive component
state stays on the server; the client just gets a circuit handle. If the Data Protection key
that signs that handle is compromised, an attacker can hijack circuits. PQ-wrapping those keys
extends the "harvest now, decrypt later" defence to every Blazor app you ship.

## Run

```bash
cd samples/Blazor.Sample
rm -rf keys/
dotnet run
```

Open the printed URL, sign in, click *Run roundtrip*. Then inspect:

```bash
ls keys/data-protection/
grep -l pqEnvelope keys/data-protection/key-*.xml
```

Every persisted key file should contain a `<pqEnvelope>` element.

---

*To God be the glory — 1 Corinthians 10:31.*
