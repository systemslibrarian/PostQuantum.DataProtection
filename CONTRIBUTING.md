# Contributing to PostQuantum.DataProtection

Thank you for considering a contribution. This document is short on purpose — read it once, ship a PR.

## Ground rules

- **Cryptography requires care.** Don't change AES-GCM, ML-KEM, HKDF, or the envelope wire format
  in a hurry. Any wire-format change needs a `FormatVersion` bump and a CHANGELOG note.
- **No new primitives.** We don't ship our own AES, our own SHA, our own ML-KEM. Use the BCL or
  BouncyCastle.
- **Tests first, code second.** Every behavioural change either fixes an existing test or comes
  with new ones. The repo runs at zero warnings; PRs that introduce warnings won't merge.
- **Honesty.** If something doesn't work yet, write it in [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

## Setting up

```bash
git clone https://github.com/systemslibrarian/PostQuantum.DataProtection
cd PostQuantum.DataProtection
dotnet restore PostQuantum.DataProtection.slnx
dotnet build PostQuantum.DataProtection.slnx -c Release
dotnet test PostQuantum.DataProtection.slnx -c Release --no-build
```

You need a .NET 8, 9, and 10 SDK installed. Building requires all three to satisfy the
multi-target.

## Running the sample

```bash
cd samples/AspNetCore.Sample
ASPNETCORE_ENVIRONMENT=Development dotnet run
```

## Running benchmarks

```bash
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*'
```

## Pull request checklist

Before opening a PR, make sure each box can be ticked:

- [ ] `dotnet build -c Release` is clean (zero warnings).
- [ ] `dotnet test -c Release` passes locally.
- [ ] `dotnet format --verify-no-changes` passes.
- [ ] New behaviour has a test.
- [ ] If the wire format changes — `FormatVersion` is bumped, `Decode` reads prior versions,
      `CHANGELOG.md` and the relevant `PackageReleaseNotes` are updated.
- [ ] If public API changes — XML docs are updated; samples and README examples still compile.
- [ ] If you added a new public type — it has XML docs (the repo treats missing docs as an error).
- [ ] `KNOWN-GAPS.md` is honest about anything you didn't finish.
- [ ] Every new top-level doc ends with `*To God be the glory — 1 Corinthians 10:31.*`

## Security issues

**Please don't open a public issue for a security bug.** Use GitHub Security Advisories on this
repo (the "Report a vulnerability" button) or email the maintainer privately. See
[SECURITY.md](SECURITY.md).

## Code style

- Repo uses `Nullable`, `ImplicitUsings`, `TreatWarningsAsErrors`, `AnalysisLevel=latest-recommended`.
- File-scoped namespaces.
- Public types and members get XML docs.
- Tests follow xUnit conventions; underscore-separated method names are allowed in the test
  project (`CA1707` is suppressed there only).

## License

By contributing you agree your contribution is licensed under the MIT license that covers the rest
of the repo.

---

*To God be the glory — 1 Corinthians 10:31.*
