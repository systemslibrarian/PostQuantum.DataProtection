// A Worker Service that uses PostQuantum.DataProtection to protect short-lived tokens it issues
// for downstream jobs. Demonstrates:
//   * One-line PQ Data Protection wiring outside ASP.NET Core
//   * Scheduled PQ keypair rotation via PostQuantumDataProtectionOptions.RotationInterval
//   * Structured logging from the library (encrypt / decrypt / rotation events)

using Microsoft.AspNetCore.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;
using WorkerService.Sample;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? "worker-sample-passphrase-not-secret";
    o.WorkFactor = KekWorkFactor.LowMemory;
    o.KeyringPath = "keys/host-keyring.bin";
});

builder.Services
    .AddDataProtection()
    .SetApplicationName("PostQuantum.DataProtection.Worker.Sample")
    .PersistKeysToFileSystem(new DirectoryInfo("keys/data-protection"))
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/pq-keystore.txt";
        o.Mode = HybridKemMode.Hybrid;
        // Demo cadence — 30 seconds — so you can watch the rotation log line in real time. A real
        // worker would set this to TimeSpan.FromDays(90) or leave it at TimeSpan.Zero and rotate
        // from an admin endpoint.
        o.RotationInterval = TimeSpan.FromSeconds(30);
    });

builder.Services.AddHostedService<TokenIssuingWorker>();

IHost host = builder.Build();
host.Run();
