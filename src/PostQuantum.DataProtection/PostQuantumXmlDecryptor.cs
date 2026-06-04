using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PostQuantum.DataProtection.Diagnostics;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;

namespace PostQuantum.DataProtection;

/// <summary>
/// ASP.NET Core Data Protection <see cref="IXmlDecryptor"/> that reverses
/// <see cref="PostQuantumXmlEncryptor"/>: parse the envelope, decapsulate the ML-KEM shared secret,
/// unwrap the classical secret (in hybrid mode), derive the AES-256-GCM key with
/// <see cref="HybridCombiner"/>, decrypt the payload, and rehydrate the original XML element.
/// </summary>
/// <remarks>
/// Activated by ASP.NET Core's <c>IActivator</c>; depends only on the same
/// <see cref="PostQuantumKeyManager"/> + <see cref="IContentKeyProvider"/> the encryptor uses.
/// Authentication failures (tampered envelope, wrong KEM keypair, wrong classical KEK) surface as
/// <see cref="CryptographicException"/> from the underlying AES-GCM or BouncyCastle decapsulator —
/// never as silent plaintext.
/// </remarks>
public sealed class PostQuantumXmlDecryptor : IXmlDecryptor
{
    private readonly PostQuantumKeyManager _pqKeys;
    private readonly IContentKeyProvider _contentKeys;
    private readonly ILogger<PostQuantumXmlDecryptor> _logger;

    /// <summary>Creates the decryptor with explicit dependencies. Intended for direct construction in tests.</summary>
    public PostQuantumXmlDecryptor(PostQuantumKeyManager pqKeys, IContentKeyProvider contentKeys, ILogger<PostQuantumXmlDecryptor>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(contentKeys);
        _pqKeys = pqKeys;
        _contentKeys = contentKeys;
        _logger = logger ?? NullLogger<PostQuantumXmlDecryptor>.Instance;
    }

    /// <summary>
    /// Creates the decryptor by resolving its dependencies from <paramref name="services"/>.
    /// </summary>
    /// <remarks>
    /// This is the constructor ASP.NET Core Data Protection's activator invokes — it stores the
    /// decryptor's type name in the persisted XML and reconstructs the decryptor at unwrap time
    /// via <c>ActivatorUtilities.CreateInstance(serviceProvider, typeName)</c>, expecting an
    /// (IServiceProvider) constructor by convention. Matches the shape of
    /// <c>DpapiXmlDecryptor</c> and the other in-box decryptors.
    /// <see cref="ActivatorUtilitiesConstructorAttribute"/> disambiguates this constructor from
    /// the explicit (<see cref="PostQuantumKeyManager"/>, <see cref="IContentKeyProvider"/>)
    /// constructor when the strict ASP.NET Core DI validator inspects the type.
    /// </remarks>
    [ActivatorUtilitiesConstructor]
    public PostQuantumXmlDecryptor(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _pqKeys = services.GetRequiredService<PostQuantumKeyManager>();
        _contentKeys = services.GetRequiredService<IContentKeyProvider>();
        _logger = services.GetService<ILogger<PostQuantumXmlDecryptor>>() ?? NullLogger<PostQuantumXmlDecryptor>.Instance;
    }

    /// <inheritdoc />
    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        long start = Stopwatch.GetTimestamp();
        using Activity? activity = Telemetry.ActivitySource.StartActivity("PostQuantum.DataProtection.Decrypt", ActivityKind.Internal);
        string mode = "unknown";

        try
        {
            if (encryptedElement.Name != XName.Get(PostQuantumXmlEncryptor.XmlElementName, PostQuantumXmlEncryptor.XmlNamespace))
            {
                Telemetry.DecryptFailures.Add(1, new KeyValuePair<string, object?>("reason", "wrong_xml_element"));
                throw new CryptographicException(
                    $"Expected an element named '{PostQuantumXmlEncryptor.XmlElementName}' in namespace '{PostQuantumXmlEncryptor.XmlNamespace}', " +
                    $"but found '{encryptedElement.Name.LocalName}' in '{encryptedElement.Name.NamespaceName}'. " +
                    "This usually means the persisted Data Protection key was wrapped by a different IXmlEncryptor and " +
                    "you mixed protectors. See docs/migration.md for the supported migration path.");
            }

            string token = encryptedElement.Value.Trim();
            HybridKemEnvelope envelope;
            try
            {
                envelope = HybridKemEnvelope.Decode(token);
            }
            catch
            {
                Telemetry.DecryptFailures.Add(1, new KeyValuePair<string, object?>("reason", "malformed_envelope"));
                throw;
            }

            mode = envelope.Mode.ToString();
            activity?.SetTag("pq.mode", mode);
            activity?.SetTag("pq.publicKeyId", envelope.PublicKeyId);

            // The envelope is self-describing; the XML attributes are diagnostic. Trust the encoded
            // envelope as the source of truth and re-check the cross-references so a malformed-but-
            // valid-looking element cannot fool us.
            try
            {
                _ = MlKem.ParseAlgorithmLabel(envelope.KemAlgorithm);
            }
            catch (CryptographicException)
            {
                Telemetry.DecryptFailures.Add(1, new KeyValuePair<string, object?>("reason", "unsupported_algorithm"));
                throw new CryptographicException(
                    $"Envelope was produced for KEM algorithm '{envelope.KemAlgorithm}', which this decryptor does not recognise. " +
                    "Supported algorithms today are ML-KEM-512, ML-KEM-768, and ML-KEM-1024.");
            }

            try
            {
                // ValueTask must not be awaited twice; AsTask() materialises it once so GetResult is safe (CA2012).
                XElement result = DecryptAsync(envelope).AsTask().GetAwaiter().GetResult();
                Telemetry.Decryptions.Add(1, new KeyValuePair<string, object?>("mode", mode));
                LogDecryptedElement(_logger, envelope.Mode, envelope.PublicKeyId, null);
                return result;
            }
            catch (KeyNotFoundException ex)
            {
                Telemetry.DecryptFailures.Add(1, new KeyValuePair<string, object?>("reason", "unknown_keypair"));
                LogUnknownKeypair(_logger, envelope.PublicKeyId, ex);
                throw new CryptographicException(
                    $"Cannot decrypt: this envelope was wrapped under PQ keypair '{envelope.PublicKeyId}', which is not loaded. " +
                    "Either the keystore was rebuilt from scratch (losing the keypair), or the host is pointed at the wrong " +
                    "PostQuantumDataProtectionOptions.KeyStorePath. Restore the keystore from backup, or point the host at the " +
                    "correct path. See docs/deployment.md §5 (Disaster recovery matrix).",
                    ex);
            }
            catch (CryptographicException ex)
            {
                Telemetry.DecryptFailures.Add(1, new KeyValuePair<string, object?>("reason", "auth_failed"));
                LogAuthFailed(_logger, envelope.PublicKeyId, ex);
                throw;
            }
        }
        finally
        {
            Telemetry.DecryptDuration.Record(
                Stopwatch.GetElapsedTime(start).TotalMilliseconds,
                new KeyValuePair<string, object?>("mode", mode));
        }
    }

    private static readonly Action<ILogger, HybridKemMode, string, Exception?> LogDecryptedElement =
        LoggerMessage.Define<HybridKemMode, string>(
            LogLevel.Debug,
            new EventId(2, "PqDataProtectionDecrypted"),
            "Decrypted Data Protection element (mode={Mode}, publicKeyId={PublicKeyId}).");

    private static readonly Action<ILogger, string, Exception?> LogUnknownKeypair =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(3, "PqDataProtectionUnknownKeypair"),
            "Failed to decrypt: envelope was wrapped under PQ keypair '{PublicKeyId}', which is not loaded. Check the keystore path and restore from backup if necessary.");

    private static readonly Action<ILogger, string, Exception?> LogAuthFailed =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(4, "PqDataProtectionAuthFailed"),
            "Failed to decrypt: AES-GCM authentication failed for envelope wrapped under PQ keypair '{PublicKeyId}'. The envelope was tampered with, or the host KEK is wrong.");

    private async ValueTask<XElement> DecryptAsync(HybridKemEnvelope envelope)
    {
        byte[] mlKemSharedSecret = await _pqKeys
            .DecapsulateAsync(envelope.PublicKeyId, envelope.KemCiphertext, cancellationToken: default)
            .ConfigureAwait(false);

        byte[]? classicalSecret = null;
        byte[]? derivedKey = null;

        try
        {
            if (envelope.Mode is HybridKemMode.Hybrid or HybridKemMode.XWingHybrid)
            {
                if (string.IsNullOrEmpty(envelope.ClassicalWrappedKeyToken))
                {
                    throw new CryptographicException($"{envelope.Mode} envelope is missing the classical wrapped-key token.");
                }

                WrappedContentKey wrappedClassical = WrappedContentKey.Decode(envelope.ClassicalWrappedKeyToken);
                using ContentKey classicalDek = await _contentKeys.UnwrapAsync(wrappedClassical).ConfigureAwait(false);
                classicalSecret = classicalDek.Key.ToArray();
                derivedKey = envelope.Mode == HybridKemMode.XWingHybrid
                    ? HybridCombiner.DeriveXWingHybrid(mlKemSharedSecret, classicalSecret, envelope.KemCiphertext, envelope.Nonce)
                    : HybridCombiner.DeriveHybrid(mlKemSharedSecret, classicalSecret, envelope.Nonce);
            }
            else
            {
                derivedKey = HybridCombiner.DeriveMlKemOnly(mlKemSharedSecret, envelope.Nonce);
            }

            byte[] plaintext = new byte[envelope.Ciphertext.Length];
            try
            {
                using var aes = new AesGcm(derivedKey, HybridKemEnvelope.TagLength);
                aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }

            try
            {
                string xml = Encoding.UTF8.GetString(plaintext);
                return XElement.Parse(xml);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlKemSharedSecret);
            if (classicalSecret is not null)
            {
                CryptographicOperations.ZeroMemory(classicalSecret);
            }

            if (derivedKey is not null)
            {
                CryptographicOperations.ZeroMemory(derivedKey);
            }
        }
    }
}
