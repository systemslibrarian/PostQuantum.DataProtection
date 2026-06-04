using System.Diagnostics.Metrics;
using System.Xml.Linq;
using PostQuantum.DataProtection.Diagnostics;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class TelemetryTests
{
    [Fact]
    public async Task Encrypt_emits_encryption_counter_and_duration_histogram()
    {
        long encryptionCount = 0;
        bool sawEncryptDuration = false;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == Telemetry.MeterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "pq_dataprotection.encryptions")
            {
                Interlocked.Add(ref encryptionCount, measurement);
            }
        });
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "pq_dataprotection.encrypt.duration" && measurement >= 0)
            {
                sawEncryptDuration = true;
            }
        });
        listener.Start();

        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            _ = encryptor.Encrypt(new XElement("p", "x"));
            _ = encryptor.Encrypt(new XElement("p", "y"));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }

        // The global Meter is shared across all running tests, and xUnit collections may execute
        // in parallel. Assert lower bounds rather than exact counts so other tests' encryptions do
        // not cause a false failure here. The two encryptions we performed must each emit at least
        // once; any larger value is fine.
        Assert.True(encryptionCount >= 2, $"Expected ≥ 2 encryption events; saw {encryptionCount}.");
        Assert.True(sawEncryptDuration);
    }

    [Fact]
    public async Task Decrypt_emits_decryption_counter()
    {
        long decryptionCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == Telemetry.MeterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "pq_dataprotection.decryptions")
            {
                Interlocked.Add(ref decryptionCount, measurement);
            }
        });
        listener.Start();

        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var encrypted = encryptor.Encrypt(new XElement("p", "x")).EncryptedElement;
            _ = decryptor.Decrypt(encrypted);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }

        Assert.True(decryptionCount >= 1, $"Expected ≥ 1 decryption event; saw {decryptionCount}.");
    }

    [Fact]
    public async Task Rotation_emits_rotation_counter()
    {
        long rotationCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == Telemetry.MeterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "pq_dataprotection.rotations")
            {
                Interlocked.Add(ref rotationCount, measurement);
            }
        });
        listener.Start();

        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync(); // first-run rotation
            _ = await pq.RotateAsync();          // explicit rotation
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }

        // Two rotations from this test (inaugural + explicit); other concurrently-running tests may
        // add more, so assert the lower bound.
        Assert.True(rotationCount >= 2, $"Expected ≥ 2 rotation events; saw {rotationCount}.");
    }
}
