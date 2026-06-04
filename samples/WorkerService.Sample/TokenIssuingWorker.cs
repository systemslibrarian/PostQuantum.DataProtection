using Microsoft.AspNetCore.DataProtection;

namespace WorkerService.Sample;

/// <summary>
/// Issues a "job token" every few seconds, protects it via Data Protection (which is wrapped by
/// PostQuantum.DataProtection), and immediately unprotects it to demonstrate the roundtrip. A
/// real worker would hand the token off to a downstream system (a queue, an HTTP call,
/// a database) and the downstream system would unprotect it.
/// </summary>
internal sealed class TokenIssuingWorker : BackgroundService
{
    private readonly IDataProtector _protector;
    private readonly ILogger<TokenIssuingWorker> _logger;
    private long _issued;

    public TokenIssuingWorker(IDataProtectionProvider dp, ILogger<TokenIssuingWorker> logger)
    {
        _protector = dp.CreateProtector("WorkerService.Sample.JobToken");
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Worker started; will issue a PQ-protected job token every 5s. Press Ctrl+C to stop.");

        while (!stoppingToken.IsCancellationRequested)
        {
            string plaintext = $"job-{Interlocked.Increment(ref _issued):D5}-at-{DateTimeOffset.UtcNow:O}";
            string token = _protector.Protect(plaintext);
            string roundtripped = _protector.Unprotect(token);

            _logger.LogInformation("Issued PQ-protected job token: payload={Payload}, tokenChars={Chars}, roundtripOk={Ok}",
                plaintext, token.Length, plaintext == roundtripped);

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
            catch (TaskCanceledException)
            {
                return;
            }
        }
    }
}
