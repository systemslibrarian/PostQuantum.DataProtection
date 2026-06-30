using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Hosting;

/// <summary>
/// Eagerly initializes the post-quantum chain on host startup when
/// <see cref="PostQuantumDataProtectionOptions.ValidateOnStartup"/> is set (the default), so a
/// misconfiguration fails fast at boot rather than lazily on the first protected request.
/// </summary>
/// <remarks>
/// Loading (or, on first run, generating) the active ML-KEM keypair exercises the whole at-rest
/// path: it resolves the host <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/>, unwraps
/// or mints a DEK, and writes to the keystore. A missing KEK, a wrong passphrase, or an unwritable
/// keystore path therefore surfaces here with an actionable message instead of inside ASP.NET Core
/// Data Protection's key-ring loader much later.
/// </remarks>
public sealed class PostQuantumStartupValidator : IHostedService
{
    private readonly PostQuantumKeyManager _pqKeys;
    private readonly IOptions<PostQuantumDataProtectionOptions> _options;
    private readonly ILogger<PostQuantumStartupValidator> _logger;

    /// <summary>Creates the validator. Registered via the DI helper, not normally constructed by hand.</summary>
    public PostQuantumStartupValidator(
        PostQuantumKeyManager pqKeys,
        IOptions<PostQuantumDataProtectionOptions> options,
        ILogger<PostQuantumStartupValidator>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(pqKeys);
        ArgumentNullException.ThrowIfNull(options);
        _pqKeys = pqKeys;
        _options = options;
        _logger = logger ?? NullLogger<PostQuantumStartupValidator>.Instance;
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Value.ValidateOnStartup)
        {
            return;
        }

        try
        {
            string activeKeyId = await _pqKeys.GetActiveKeyIdAsync(cancellationToken).ConfigureAwait(false);
            LogValidated(_logger, activeKeyId, null);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "PostQuantum.DataProtection failed to initialize on startup. The active ML-KEM keypair could not be " +
                "loaded or generated. Common causes: the host IContentKeyProvider is missing or misconfigured (did you " +
                "call AddPostQuantumKeyManagement(...) with the right passphrase?), the keystore path is not writable, " +
                "or a previously-generated keypair cannot be unwrapped under the current KEK. " +
                "See docs/troubleshooting.md. To defer this check to first use instead of failing at boot, set " +
                "PostQuantumDataProtectionOptions.ValidateOnStartup = false.",
                ex);
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static readonly Action<ILogger, string, Exception?> LogValidated =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(25, "PqStartupValidated"),
            "PostQuantum.DataProtection initialized on startup; active key is '{ActiveKeyId}'.");
}
