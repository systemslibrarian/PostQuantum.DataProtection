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
    /// given connection string. Internally creates a single <see cref="ConnectionMultiplexer"/>.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionRedis(
        this IServiceCollection services,
        string connectionString,
        string prefix = RedisPostQuantumKeyStore.DefaultPrefix)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.RemoveAll<IPostQuantumKeyStore>();
        services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(connectionString));
        services.AddSingleton<IPostQuantumKeyStore>(sp =>
        {
            IConnectionMultiplexer mux = sp.GetRequiredService<IConnectionMultiplexer>();
            IRedisKeyStoreClient client = new RedisDatabaseAdapter(mux.GetDatabase());
            return new RedisPostQuantumKeyStore(client, prefix);
        });

        return services;
    }
}
