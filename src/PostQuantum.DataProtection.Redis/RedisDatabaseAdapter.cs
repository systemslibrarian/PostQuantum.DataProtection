using StackExchange.Redis;

namespace PostQuantum.DataProtection.Redis;

internal sealed class RedisDatabaseAdapter : IRedisKeyStoreClient
{
    private readonly IDatabase _db;

    public RedisDatabaseAdapter(IDatabase db)
    {
        ArgumentNullException.ThrowIfNull(db);
        _db = db;
    }

    public async ValueTask<string?> StringGetAsync(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RedisValue value = await _db.StringGetAsync(key).ConfigureAwait(false);
        return value.IsNullOrEmpty ? null : (string?)value;
    }

    public async ValueTask StringSetAsync(string key, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = await _db.StringSetAsync(key, value).ConfigureAwait(false);
    }

    public async ValueTask<string?> HashGetAsync(string key, string field, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RedisValue value = await _db.HashGetAsync(key, field).ConfigureAwait(false);
        return value.IsNullOrEmpty ? null : (string?)value;
    }

    public async ValueTask<IReadOnlyDictionary<string, string>> HashGetAllAsync(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HashEntry[] entries = await _db.HashGetAllAsync(key).ConfigureAwait(false);
        var result = new Dictionary<string, string>(entries.Length, StringComparer.Ordinal);
        foreach (HashEntry entry in entries)
        {
            string? field = entry.Name.ToString();
            string? value = entry.Value.ToString();
            if (field is not null && value is not null)
            {
                result[field] = value;
            }
        }
        return result;
    }

    public async ValueTask HashSetAsync(string key, string field, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = await _db.HashSetAsync(key, field, value).ConfigureAwait(false);
    }

    public async ValueTask<bool> HashDeleteAsync(string key, string field, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _db.HashDeleteAsync(key, field).ConfigureAwait(false);
    }
}
