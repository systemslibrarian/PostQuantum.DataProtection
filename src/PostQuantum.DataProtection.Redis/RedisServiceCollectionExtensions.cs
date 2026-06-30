using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.DataProtection.Keys;
using PostQuantum.DataProtection.Redis;
using StackExchange.Redis;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI extensions that register <see cref="RedisPostQuantumKeyStore"/>.
/// </summary>
public static class RedisPostQuantumServiceCollectionExtensions
{
    /// <summary>
    /// Replaces the registered <see cref="IPostQuantumKeyStore"/> with a Redis-backed store using the
    /// given connection string, and registers a Redis-backed <see cref="IRotationLock"/> so scheduled
    /// rotation is single-leader across replicas. Internally creates a single
    /// <see cref="ConnectionMultiplexer"/>.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionRedis(
        this IServiceCollection services,
        string connectionString,
        string prefix = RedisPostQuantumKeyStore.DefaultPrefix)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.RemoveAll<IPostQuantumKeyStore>();
        services.RemoveAll<IRotationLock>();
        services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(connectionString));
        services.AddSingleton<IRedisKeyStoreClient>(sp =>
            new RedisDatabaseAdapter(sp.GetRequiredService<IConnectionMultiplexer>().GetDatabase()));
        services.AddSingleton<IPostQuantumKeyStore>(sp =>
            new RedisPostQuantumKeyStore(sp.GetRequiredService<IRedisKeyStoreClient>(), prefix));
        services.AddSingleton<IRotationLock>(sp =>
            new RedisRotationLock(sp.GetRequiredService<IRedisKeyStoreClient>(), prefix));

        return services;
    }
}
