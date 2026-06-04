using System.Collections.Concurrent;
using PostQuantum.DataProtection.Redis;

namespace PostQuantum.DataProtection.Redis.Tests;

public sealed class InMemoryRedisClient : IRedisKeyStoreClient
{
    private readonly ConcurrentDictionary<string, string> _strings = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _hashes = new(StringComparer.Ordinal);

    public ValueTask<string?> StringGetAsync(string key, CancellationToken cancellationToken) =>
        new(_strings.TryGetValue(key, out string? v) ? v : null);

    public ValueTask StringSetAsync(string key, string value, CancellationToken cancellationToken)
    {
        _strings[key] = value;
        return ValueTask.CompletedTask;
    }

    public ValueTask<string?> HashGetAsync(string key, string field, CancellationToken cancellationToken)
    {
        if (_hashes.TryGetValue(key, out var hash) && hash.TryGetValue(field, out string? v))
        {
            return new ValueTask<string?>(v);
        }
        return new ValueTask<string?>((string?)null);
    }

    public ValueTask<IReadOnlyDictionary<string, string>> HashGetAllAsync(string key, CancellationToken cancellationToken)
    {
        if (_hashes.TryGetValue(key, out var hash))
        {
            return new ValueTask<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>(hash, StringComparer.Ordinal));
        }
        return new ValueTask<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>());
    }

    public ValueTask HashSetAsync(string key, string field, string value, CancellationToken cancellationToken)
    {
        var hash = _hashes.GetOrAdd(key, _ => new ConcurrentDictionary<string, string>(StringComparer.Ordinal));
        hash[field] = value;
        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> HashDeleteAsync(string key, string field, CancellationToken cancellationToken)
    {
        if (_hashes.TryGetValue(key, out var hash))
        {
            return new ValueTask<bool>(hash.TryRemove(field, out _));
        }
        return new ValueTask<bool>(false);
    }
}
