using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
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

    /// <summary>Creates the decryptor with explicit dependencies. Intended for direct construction in tests.</summary>
    public PostQuantumXmlDecryptor(PostQuantumKeyManager pqKeys, IContentKeyProvider contentKeys)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(contentKeys);
        _pqKeys = pqKeys;
        _contentKeys = contentKeys;
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
    }

    /// <inheritdoc />
    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        if (encryptedElement.Name != XName.Get(PostQuantumXmlEncryptor.XmlElementName, PostQuantumXmlEncryptor.XmlNamespace))
        {
            throw new CryptographicException(
                $"Expected an element named '{PostQuantumXmlEncryptor.XmlElementName}' in namespace '{PostQuantumXmlEncryptor.XmlNamespace}'.");
        }

        string token = encryptedElement.Value.Trim();
        HybridKemEnvelope envelope = HybridKemEnvelope.Decode(token);

        // The envelope is self-describing; the XML attributes are diagnostic. Trust the encoded
        // envelope as the source of truth and re-check the cross-references so a malformed-but-
        // valid-looking element cannot fool us.
        if (envelope.KemAlgorithm != MlKem.AlgorithmName)
        {
            throw new CryptographicException(
                $"Envelope was produced for KEM algorithm '{envelope.KemAlgorithm}'; this decryptor only supports '{MlKem.AlgorithmName}'.");
        }

        // ValueTask must not be awaited twice; AsTask() materialises it once so GetResult is safe (CA2012).
        return DecryptAsync(envelope).AsTask().GetAwaiter().GetResult();
    }

    private async ValueTask<XElement> DecryptAsync(HybridKemEnvelope envelope)
    {
        byte[] mlKemSharedSecret = await _pqKeys
            .DecapsulateAsync(envelope.PublicKeyId, envelope.KemCiphertext, cancellationToken: default)
            .ConfigureAwait(false);

        byte[]? classicalSecret = null;
        byte[]? derivedKey = null;

        try
        {
            if (envelope.Mode == HybridKemMode.Hybrid)
            {
                if (string.IsNullOrEmpty(envelope.ClassicalWrappedKeyToken))
                {
                    throw new CryptographicException("Hybrid envelope is missing the classical wrapped-key token.");
                }

                WrappedContentKey wrappedClassical = WrappedContentKey.Decode(envelope.ClassicalWrappedKeyToken);
                using ContentKey classicalDek = await _contentKeys.UnwrapAsync(wrappedClassical).ConfigureAwait(false);
                classicalSecret = classicalDek.Key.ToArray();
                derivedKey = HybridCombiner.DeriveHybrid(mlKemSharedSecret, classicalSecret, envelope.Nonce);
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
