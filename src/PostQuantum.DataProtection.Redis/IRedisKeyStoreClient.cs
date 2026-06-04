namespace PostQuantum.DataProtection.Redis;

/// <summary>
/// Narrow seam over the bits of <c>StackExchange.Redis.IDatabase</c> that
/// <see cref="RedisPostQuantumKeyStore"/> uses. Lets the store be unit-tested against an in-memory
/// fake without standing up a Redis instance.
/// </summary>
public interface IRedisKeyStoreClient
{
    /// <summary>Reads a string-valued key.</summary>
    ValueTask<string?> StringGetAsync(string key, CancellationToken cancellationToken);

    /// <summary>Writes a string-valued key.</summary>
    ValueTask StringSetAsync(string key, string value, CancellationToken cancellationToken);

    /// <summary>Reads a single field from a hash.</summary>
    ValueTask<string?> HashGetAsync(string key, string field, CancellationToken cancellationToken);

    /// <summary>Reads every (field, value) entry of a hash.</summary>
    ValueTask<IReadOnlyDictionary<string, string>> HashGetAllAsync(string key, CancellationToken cancellationToken);

    /// <summary>Writes a single (field, value) into a hash.</summary>
    ValueTask HashSetAsync(string key, string field, string value, CancellationToken cancellationToken);

    /// <summary>Deletes a single field from a hash. Returns true if a delete happened.</summary>
    ValueTask<bool> HashDeleteAsync(string key, string field, CancellationToken cancellationToken);
}
