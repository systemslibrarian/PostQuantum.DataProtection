using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// End-to-end smoke tests: register the library as a real Data Protection consumer would, protect
/// a payload, restart the host, and confirm the payload still unprotects.
/// </summary>
public sealed class DataProtectionIntegrationTests
{
    [Fact]
    public void Protect_then_Unprotect_round_trips_through_ASP_NET_Core_Data_Protection()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("user-session-state-the-cookie-protects");
            byte[] protectedBytes;

            using (ServiceProvider sp = BuildHost(tempDir))
            {
                IDataProtectionProvider provider = sp.GetRequiredService<IDataProtectionProvider>();
                IDataProtector protector = provider.CreateProtector("test.purpose");
                protectedBytes = protector.Protect(plaintext);
            }

            // Spin up a *new* host with the same keys directory and PQ keystore on disk; the
            // protected payload must still unprotect — that's the whole point of persistence.
            using (ServiceProvider sp = BuildHost(tempDir))
            {
                IDataProtectionProvider provider = sp.GetRequiredService<IDataProtectionProvider>();
                IDataProtector protector = provider.CreateProtector("test.purpose");
                byte[] unprotected = protector.Unprotect(protectedBytes);

                Assert.Equal(plaintext, unprotected);
            }
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Persisted_DP_key_file_contains_a_pqEnvelope_element()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            using (ServiceProvider sp = BuildHost(tempDir))
            {
                IDataProtectionProvider provider = sp.GetRequiredService<IDataProtectionProvider>();
                _ = provider.CreateProtector("force.key.generation").Protect(Encoding.UTF8.GetBytes("x"));
            }

            string dpDir = Path.Combine(tempDir, "data-protection");
            string[] keyFiles = Directory.GetFiles(dpDir, "key-*.xml");
            Assert.NotEmpty(keyFiles);

            string keyXml = File.ReadAllText(keyFiles[0]);
            Assert.Contains("pqEnvelope", keyXml, StringComparison.Ordinal);
            Assert.Contains(PostQuantumXmlEncryptor.XmlNamespace, keyXml, StringComparison.Ordinal);
            Assert.Contains("PostQuantum.DataProtection.PostQuantumXmlDecryptor", keyXml, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    private static ServiceProvider BuildHost(string tempDir)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // Wire PostQuantum.KeyManagement (the IContentKeyProvider). The KeyringPath persists the
        // host KEK across the two service-provider lifetimes in this test — without it, the second
        // host would derive a different random salt and the previously-wrapped PQ secret key would
        // fail to unwrap, masking the integration shape we are actually trying to verify.
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = TestDefaults.Passphrase;
            o.WorkFactor = KekWorkFactor.LowMemory;
            o.KeyringPath = Path.Combine(tempDir, "host-keyring.bin");
        });

        // Wire ASP.NET Core Data Protection with our PQ encryptor.
        services
            .AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(tempDir, "data-protection")))
            .ProtectKeysWithPostQuantum(o =>
            {
                o.KeyStorePath = Path.Combine(tempDir, "pq.txt");
                o.Mode = HybridKemMode.Hybrid;
            });

        return services.BuildServiceProvider();
    }
}
