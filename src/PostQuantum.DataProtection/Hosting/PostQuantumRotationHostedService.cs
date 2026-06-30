using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Hosting;

/// <summary>
/// Background service that periodically calls <see cref="PostQuantumKeyManager.RotateAsync"/> to
/// generate a fresh ML-KEM keypair. Old keypairs stay in the loaded set so previously-wrapped Data
/// Protection keys keep decrypting; only the *active* keypair changes.
/// </summary>
/// <remarks>
/// <para>
/// Driven by <see cref="PostQuantumDataProtectionOptions.RotationInterval"/>. When the interval is
/// <see langword="null"/> (the default), the service does nothing — rotation stays a manual call.
/// Set the interval to e.g. <c>TimeSpan.FromDays(90)</c> to match a typical Data Protection key
/// rotation cadence.
/// </para>
/// <para>
/// The first rotation runs after the configured interval has elapsed, not immediately on startup.
/// (The inaugural keypair already exists by the time this service runs.) Subsequent rotations are
/// spaced by the interval. If a rotation fails, the next one runs at the next interval — failures
/// are logged but do not throw the host down.
/// </para>
/// <para>
/// Before each rotation the service acquires the registered <see cref="IRotationLock"/>. With the
/// default <see cref="NullRotationLock"/> the lease is always granted (single-writer assumption).
/// In a multi-replica deployment, register a distributed lock so only the replica that wins the
/// lease rotates in a given window; the others skip and pick up the new active key on their next
/// load.
/// </para>
/// </remarks>
public sealed class PostQuantumRotationHostedService : BackgroundService
{
    // The rotation lease is held only for the brief moment a rotation takes. Keep it comfortably
    // longer than a single RotateAsync (key-gen + one KEK wrap + one store write) but short enough
    // that a crashed leader does not block rotation for long.
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(5);

    private readonly PostQuantumKeyManager _pqKeys;
    private readonly IRotationLock _rotationLock;
    private readonly IOptionsMonitor<PostQuantumDataProtectionOptions> _options;
    private readonly ILogger<PostQuantumRotationHostedService> _logger;

    /// <summary>Creates the rotation service. Registered via the DI helper, not normally constructed by hand.</summary>
    public PostQuantumRotationHostedService(
        PostQuantumKeyManager pqKeys,
        IOptionsMonitor<PostQuantumDataProtectionOptions> options,
        IRotationLock? rotationLock = null,
        ILogger<PostQuantumRotationHostedService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(options);
        _pqKeys = pqKeys;
        _options = options;
        _rotationLock = rotationLock ?? NullRotationLock.Instance;
        _logger = logger ?? NullLogger<PostQuantumRotationHostedService>.Instance;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan? configured = _options.CurrentValue.RotationInterval;
        if (configured is not { } interval || interval <= TimeSpan.Zero)
        {
            LogDisabled(_logger, null);
            return;
        }

        LogStarted(_logger, interval, null);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                return;
            }

            try
            {
                await using IAsyncDisposable? lease = await _rotationLock.TryAcquireAsync(LeaseDuration, stoppingToken).ConfigureAwait(false);
                if (lease is null)
                {
                    LogRotationSkipped(_logger, null);
                    continue;
                }

                string newKeyId = await _pqKeys.RotateAsync(stoppingToken).ConfigureAwait(false);
                LogRotated(_logger, newKeyId, null);
            }
            catch (OperationCanceledException)
            {
                return;
            }
#pragma warning disable CA1031 // catch general exception — we deliberately keep the host alive across rotation failures
            catch (Exception ex)
            {
                LogRotationFailed(_logger, interval, ex);
            }
#pragma warning restore CA1031
        }
    }

    private static readonly Action<ILogger, Exception?> LogDisabled =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(20, "PqRotationDisabled"),
            "Scheduled PQ keypair rotation is disabled (RotationInterval is null).");

    private static readonly Action<ILogger, TimeSpan, Exception?> LogStarted =
        LoggerMessage.Define<TimeSpan>(
            LogLevel.Information,
            new EventId(21, "PqRotationStarted"),
            "Scheduled PQ keypair rotation enabled; first rotation in {Interval}.");

    private static readonly Action<ILogger, string, Exception?> LogRotated =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(22, "PqRotationCompleted"),
            "Scheduled PQ keypair rotation completed; new active key '{KeyId}'.");

    private static readonly Action<ILogger, TimeSpan, Exception?> LogRotationFailed =
        LoggerMessage.Define<TimeSpan>(
            LogLevel.Error,
            new EventId(23, "PqRotationFailed"),
            "Scheduled PQ keypair rotation failed; the host is still alive and will retry in {Interval}.");

    private static readonly Action<ILogger, Exception?> LogRotationSkipped =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(24, "PqRotationSkipped"),
            "Skipped scheduled PQ keypair rotation: another replica holds the rotation lease this window.");
}
