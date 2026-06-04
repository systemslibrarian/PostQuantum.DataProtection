# Supply chain

This document explains what `PostQuantum.DataProtection` does to keep its build, its dependencies,
and its published artifacts honest — and how to verify any of it yourself.

## What ships in this repo

Two artifacts per package per release:

- `PostQuantum.DataProtection.<version>.nupkg` — the library (multi-target
  net8.0 / net9.0 / net10.0).
- `PostQuantum.DataProtection.<version>.snupkg` — the symbol package, with embedded source links.

That is the whole surface area. No native libraries, no installers, no PowerShell modules.

## Build posture

Every project in this repo turns on the following — `dotnet pack -c Release` enforces them:

| Property                          | Value         | Why                                                          |
| --------------------------------- | ------------- | ------------------------------------------------------------ |
| `Deterministic`                   | `true`        | Re-running pack on the same commit must produce byte-identical output. |
| `ContinuousIntegrationBuild`      | `true` (CI)   | Strips local paths from PDBs so they only depend on the commit. |
| `EmbedUntrackedSources`           | `true`        | Generated files that are not under source control still ship in the symbol package. |
| `IncludeSymbols`                  | `true`        | Always emit a `.snupkg` alongside the `.nupkg`.              |
| `SymbolPackageFormat`             | `snupkg`      | Modern, nuget.org-native symbol format.                      |
| `PublishRepositoryUrl`            | `true`        | Embeds the GitHub URL in the package metadata.               |
| `EnablePackageValidation`         | `true`        | Runs the .NET Package Validation analyser and fails the build on API surface drift between framework targets. |
| `GenerateDocumentationFile`       | `true`        | Ships the XML doc file in the package.                       |
| `TreatWarningsAsErrors`           | `true`        | Zero-warning policy across the repo.                         |
| `Microsoft.SourceLink.GitHub`     | referenced    | Adds GitHub source URLs to every PDB entry.                  |

`TreatWarningsAsErrors` plus the `latest-recommended` analyser ruleset is the actual enforcement
mechanism — every PR that lands in this repo passes the same gate as a release build.

## Dependencies

Pinned, audited, all from nuget.org:

| Package                                                | Version          | What it is                          | Where the source lives                                |
| ------------------------------------------------------ | ---------------- | ----------------------------------- | ----------------------------------------------------- |
| `BouncyCastle.Cryptography`                            | 2.6.2            | ML-KEM-768 (FIPS 203)               | https://github.com/bcgit/bc-csharp                    |
| `PostQuantum.KeyManagement`                            | 0.4.0-preview.2  | Classical envelope-encryption KEK   | https://github.com/systemslibrarian/PostQuantum.KeyManagement |
| `Microsoft.AspNetCore.DataProtection.Abstractions`     | 8.0.27           | IXmlEncryptor / IXmlDecryptor       | https://github.com/dotnet/aspnetcore                  |
| `Microsoft.AspNetCore.DataProtection.Extensions`       | 8.0.27           | DI extensions                       | https://github.com/dotnet/aspnetcore                  |
| `Microsoft.Extensions.DependencyInjection.Abstractions`| 8.0.2            | DI primitives                       | https://github.com/dotnet/runtime                     |
| `Microsoft.Extensions.Options`                         | 8.0.2            | IOptions<>                          | https://github.com/dotnet/runtime                     |
| `Microsoft.SourceLink.GitHub`                          | 8.0.0            | SourceLink                          | https://github.com/dotnet/sourcelink                  |
| `System.Security.Cryptography.Xml`                     | 8.0.3 (pinned)   | Transitive — explicit override      | https://github.com/dotnet/runtime                     |

### Transitive dependency hygiene

The `.csproj` explicitly pins `System.Security.Cryptography.Xml` to the patched **8.0.3** because
the 8.0.x line pre-8.0.3 carries two published high-severity advisories:

- [GHSA-37gx-xxp4-5rgx](https://github.com/advisories/GHSA-37gx-xxp4-5rgx) — XML signature
  validation issues.
- [GHSA-w3x6-4m5h-cxqf](https://github.com/advisories/GHSA-w3x6-4m5h-cxqf) — XML processing.

`Microsoft.AspNetCore.DataProtection.Extensions` transitively brings in this package; the pin
guarantees no transitive resolution can land on an unpatched version. The repo's
`Directory.Build.props` keeps `TreatWarningsAsErrors=true`, so any future advisory NuGet flags on
a referenced package fails the build until the dependency is bumped.

## Generating an SBOM

The package metadata is SBOM-generator-friendly: every `<PackageReference>` is explicit and
versioned in the `.csproj`. Two common recipes:

### CycloneDX (`dotnet-CycloneDX`)

```bash
dotnet tool install --global CycloneDX
dotnet CycloneDX src/PostQuantum.DataProtection/PostQuantum.DataProtection.csproj -o artifacts/sbom -j
# produces artifacts/sbom/bom.json (CycloneDX 1.4 JSON)
```

### Microsoft SBOM Tool

```bash
dotnet tool install --global Microsoft.Sbom.DotNetTool
sbom-tool generate -b src/PostQuantum.DataProtection/bin/Release -bc src/PostQuantum.DataProtection -pn PostQuantum.DataProtection -pv 0.1.0-preview.1 -nsb https://github.com/systemslibrarian/PostQuantum.DataProtection
# produces _manifest/spdx_2.2/ under the build output directory
```

Both tools read the same explicit `<PackageReference>` graph, so the SBOMs they produce should
agree on the dependency set. We do not ship a pre-built SBOM in the package itself because the
right format for your environment depends on what consumes it (SPDX for some compliance regimes,
CycloneDX for OWASP Dependency-Track, etc.).

## Verifying a published `.nupkg`

```bash
# 1. Download .nupkg and .snupkg from nuget.org.
curl -L -o PostQuantum.DataProtection.0.1.0-preview.1.nupkg \
  https://api.nuget.org/v3-flatcontainer/postquantum.dataprotection/0.1.0-preview.1/postquantum.dataprotection.0.1.0-preview.1.nupkg

# 2. Confirm SourceLink works — the .snupkg should embed GitHub URLs for every source file.
dotnet tool install --global sourcelink
sourcelink test PostQuantum.DataProtection.0.1.0-preview.1.nupkg

# 3. Reproduce the build from the matching commit.
git clone https://github.com/systemslibrarian/PostQuantum.DataProtection
cd PostQuantum.DataProtection
git checkout v0.1.0-preview.1
dotnet pack -c Release -o /tmp/local-pack

# 4. Compare the SHA-256 of the local pack and the nuget.org download.
sha256sum /tmp/local-pack/PostQuantum.DataProtection.0.1.0-preview.1.nupkg
sha256sum PostQuantum.DataProtection.0.1.0-preview.1.nupkg
# the values should match.
```

If they do not match, **do not ship** — open an issue with both hashes and the commit SHA, and
we will figure out what drifted.

## Verifying the BouncyCastle dependency

BouncyCastle is the only third-party cryptographic source code in this library. To verify the
build of `BouncyCastle.Cryptography 2.6.2`:

```bash
curl -L -o bc.nupkg https://api.nuget.org/v3-flatcontainer/bouncycastle.cryptography/2.6.2/bouncycastle.cryptography.2.6.2.nupkg
unzip -l bc.nupkg | head -40
# inspect the assemblies and confirm the namespaces present include Org.BouncyCastle.Crypto.Kems
# (MLKemEncapsulator / MLKemDecapsulator) and Org.BouncyCastle.Crypto.Parameters
# (MLKemParameters, MLKemPublicKeyParameters, MLKemPrivateKeyParameters).
```

The BouncyCastle source repo is https://github.com/bcgit/bc-csharp and the project publishes
signed releases.

---

*To God be the glory — 1 Corinthians 10:31.*
