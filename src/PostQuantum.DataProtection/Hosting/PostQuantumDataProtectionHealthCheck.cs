using System.Xml.Linq;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;

namespace PostQuantum.DataProtection.Hosting;

/// <summary>
/// Exercises a real PQ envelope roundtrip — encapsulate, derive, AES-GCM encrypt, decapsulate,
/// decrypt — using the host's actual <see cref="PostQuantumKeyManager"/> and
/// <see cref="IContentKeyProvider"/>. Anything that breaks the chain (missing keystore, wrong
/// host KEK, BC version drift) surfaces as <see cref="HealthStatus.Unhealthy"/>.
/// </summary>
/// <remarks>
/// The check uses a tiny disposable XML element (10 bytes of payload) so the cryptographic work is
/// dominated by ML-KEM encapsulation + decapsulation — microseconds on modern hardware. Safe to
/// call on every probe interval.
/// </remarks>
public sealed class PostQuantumDataProtectionHealthCheck : IHealthCheck
{
    private readonly PostQuantumKeyManager _pqKeys;
    private readonly IContentKeyProvider _contentKeys;

    /// <summary>Creates the check.</summary>
    public PostQuantumDataProtectionHealthCheck(PostQuantumKeyManager pqKeys, IContentKeyProvider contentKeys)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(contentKeys);
        _pqKeys = pqKeys;
        _contentKeys = contentKeys;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var encryptor = new PostQuantumXmlEncryptor(_pqKeys, _contentKeys, HybridKemMode.Hybrid);
            var decryptor = new PostQuantumXmlDecryptor(_pqKeys, _contentKeys);

            var probe = new XElement("pq-dp-healthcheck-probe", "ok");
            var encrypted = encryptor.Encrypt(probe).EncryptedElement;
            var roundtripped = decryptor.Decrypt(encrypted);

            if (!string.Equals(roundtripped.ToString(SaveOptions.DisableFormatting),
                               probe.ToString(SaveOptions.DisableFormatting), StringComparison.Ordinal))
            {
                return HealthCheckResult.Unhealthy(
                    "PQ data-protection roundtrip succeeded but the decrypted element did not match the probe.");
            }

            IReadOnlyList<PostQuantumKeyDescriptor> keys = await _pqKeys.ListKeysAsync(cancellationToken).ConfigureAwait(false);
            string activeId = await _pqKeys.GetActiveKeyIdAsync(cancellationToken).ConfigureAwait(false);

            return HealthCheckResult.Healthy(
                $"PQ data-protection roundtrip OK. {keys.Count} keypair(s) loaded; active: {activeId}.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("PQ data-protection roundtrip failed.", ex);
        }
    }
}
