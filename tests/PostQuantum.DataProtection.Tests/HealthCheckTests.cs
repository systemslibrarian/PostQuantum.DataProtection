using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using PostQuantum.DataProtection.Hosting;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class HealthCheckTests
{
    [Fact]
    public async Task Returns_healthy_when_roundtrip_succeeds()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var check = new PostQuantumDataProtectionHealthCheck(pq, keys);
            HealthCheckResult result = await check.CheckHealthAsync(new HealthCheckContext());

            Assert.Equal(HealthStatus.Healthy, result.Status);
            Assert.Contains("roundtrip OK", result.Description!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task AddPostQuantumDataProtection_registers_the_check_in_the_DI_container()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = TestDefaults.Passphrase;
            o.WorkFactor = KekWorkFactor.LowMemory;
        });

        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            services
                .AddDataProtection()
                .ProtectKeysWithPostQuantum(o =>
                {
                    o.KeyStorePath = Path.Combine(tempDir, "pq.txt");
                });

            services.AddHealthChecks().AddPostQuantumDataProtection();

            using ServiceProvider sp = services.BuildServiceProvider();
            HealthCheckService svc = sp.GetRequiredService<HealthCheckService>();
            HealthReport report = await svc.CheckHealthAsync();

            Assert.True(report.Entries.ContainsKey("post-quantum-data-protection"));
            Assert.Equal(HealthStatus.Healthy, report.Entries["post-quantum-data-protection"].Status);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
