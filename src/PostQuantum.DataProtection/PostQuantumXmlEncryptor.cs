using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using PostQuantum.DataProtection.Diagnostics;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;

namespace PostQuantum.DataProtection;

/// <summary>
/// ASP.NET Core Data Protection <see cref="IXmlEncryptor"/> that wraps each persisted Data
/// Protection key under an ML-KEM-768 + AES-256-GCM hybrid envelope.
/// </summary>
/// <remarks>
/// <para>
/// One instance per host. The encryptor encapsulates a fresh shared secret against the active
/// post-quantum keypair on every call, mints a fresh DEK from the host
/// <see cref="IContentKeyProvider"/> in <see cref="HybridKemMode.Hybrid"/> mode, derives the
/// AES-256-GCM key with <see cref="HybridCombiner"/>, encrypts the original XML payload, and emits
/// a single XML element carrying the encoded <see cref="HybridKemEnvelope"/>.
/// </para>
/// <para>
/// The returned <see cref="EncryptedXmlInfo"/> names <see cref="PostQuantumXmlDecryptor"/> as its
/// decryptor; ASP.NET Core's <c>IActivator</c> resolves an instance from DI at decrypt time.
/// </para>
/// </remarks>
public sealed class PostQuantumXmlEncryptor : IXmlEncryptor
{
    private readonly PostQuantumKeyManager _pqKeys;
    private readonly IContentKeyProvider _contentKeys;
    private readonly HybridKemMode _mode;

    /// <summary>
    /// XML namespace pinned by the format. Keep stable across versions — wire-format changes go
    /// through <see cref="HybridKemEnvelope.CurrentFormatVersion"/>, not by switching namespaces.
    /// </summary>
    public const string XmlNamespace = "https://schemas.systemslibrarian.dev/pq-dataprotection/2026/01";

    /// <summary>Name of the single XML element this encryptor produces.</summary>
    public const string XmlElementName = "pqEnvelope";

    /// <summary>Creates an encryptor that targets the active keypair of <paramref name="pqKeys"/>.</summary>
    public PostQuantumXmlEncryptor(PostQuantumKeyManager pqKeys, IContentKeyProvider contentKeys, HybridKemMode mode = HybridKemMode.Hybrid)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(contentKeys);
        _pqKeys = pqKeys;
        _contentKeys = contentKeys;
        _mode = mode;
    }

    /// <inheritdoc />
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);

        long start = Stopwatch.GetTimestamp();
        using Activity? activity = Telemetry.ActivitySource.StartActivity("PostQuantum.DataProtection.Encrypt", ActivityKind.Internal);
        activity?.SetTag("pq.mode", _mode.ToString());

        try
        {
            // IXmlEncryptor is synchronous by contract. The PQ key manager and content-key provider
            // expose async APIs; ASP.NET Core's data-protection key ring loader calls Encrypt on the
            // startup thread (or under a sync-over-async wrapper of its own), so a single blocking
            // join here is acceptable and is the same pattern PostQuantum.KeyManagement's DI hosting
            // uses for the keyring store.
            // ValueTask must not be awaited twice; AsTask() materialises it once so GetResult is safe (CA2012).
            HybridKemEnvelope envelope = EncryptAsync(plaintextElement).AsTask().GetAwaiter().GetResult();

            var encryptedElement = new XElement(
                XName.Get(XmlElementName, XmlNamespace),
                new XAttribute("version", HybridKemEnvelope.CurrentFormatVersion),
                new XAttribute("mode", envelope.Mode.ToString()),
                new XAttribute("publicKeyId", envelope.PublicKeyId),
                envelope.Encode());

            activity?.SetTag("pq.publicKeyId", envelope.PublicKeyId);
            Telemetry.Encryptions.Add(1, new KeyValuePair<string, object?>("mode", _mode.ToString()));
            return new EncryptedXmlInfo(encryptedElement, typeof(PostQuantumXmlDecryptor));
        }
        finally
        {
            Telemetry.EncryptDuration.Record(
                Stopwatch.GetElapsedTime(start).TotalMilliseconds,
                new KeyValuePair<string, object?>("mode", _mode.ToString()));
        }
    }

    private async ValueTask<HybridKemEnvelope> EncryptAsync(XElement plaintextElement)
    {
        (string activeKeyId, byte[] publicKey) = await _pqKeys.GetPublicKeyAsync(cancellationToken: default).ConfigureAwait(false);

        (byte[] kemCiphertext, byte[] mlKemSharedSecret) = MlKem.Encapsulate(publicKey);
        byte[]? classicalSecret = null;
        string classicalWrappedToken = string.Empty;
        ContentKey? classicalDek = null;
        byte[] nonce = RandomNumberGenerator.GetBytes(HybridKemEnvelope.NonceLength);
        byte[]? derivedKey = null;

        try
        {
            if (_mode == HybridKemMode.Hybrid)
            {
                classicalDek = await _contentKeys.CreateContentKeyAsync().ConfigureAwait(false);
                classicalSecret = classicalDek.Key.ToArray();
                classicalWrappedToken = classicalDek.WrappedKey.Encode();
                derivedKey = HybridCombiner.DeriveHybrid(mlKemSharedSecret, classicalSecret, nonce);
            }
            else
            {
                derivedKey = HybridCombiner.DeriveMlKemOnly(mlKemSharedSecret, nonce);
            }

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[HybridKemEnvelope.TagLength];

            using (var aes = new AesGcm(derivedKey, HybridKemEnvelope.TagLength))
            {
                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            }

            return new HybridKemEnvelope
            {
                Mode = _mode,
                KemAlgorithm = MlKem.AlgorithmName,
                PublicKeyId = activeKeyId,
                KemCiphertext = kemCiphertext,
                ClassicalWrappedKeyToken = classicalWrappedToken,
                Nonce = nonce,
                Tag = tag,
                Ciphertext = ciphertext,
            };
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

            classicalDek?.Dispose();
        }
    }
}
