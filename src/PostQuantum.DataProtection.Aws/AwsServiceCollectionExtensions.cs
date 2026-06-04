using Amazon.SecretsManager;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using PostQuantum.DataProtection.Aws;
using PostQuantum.DataProtection.Keys;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI extensions that swap the bundled file store for the AWS Secrets Manager-backed
/// <see cref="AwsSecretsManagerPostQuantumKeyStore"/>.
/// </summary>
public static class AwsPostQuantumServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="IPostQuantumKeyStore"/> backed by AWS Secrets Manager. Call after
    /// <c>AddDataProtection().ProtectKeysWithPostQuantum(...)</c> to replace the default file
    /// store.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionAws(
        this IServiceCollection services,
        Action<AwsDataProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<AwsDataProtectionOptions>().Configure(configure);

        services.RemoveAll<IPostQuantumKeyStore>();
        services.AddSingleton<IPostQuantumKeyStore>(static sp =>
        {
            AwsDataProtectionOptions o = sp.GetRequiredService<IOptions<AwsDataProtectionOptions>>().Value;

            IAmazonSecretsManager rawClient = (o.Credentials, o.Region) switch
            {
                (not null, not null) => new AmazonSecretsManagerClient(o.Credentials, o.Region),
                (not null, null) => new AmazonSecretsManagerClient(o.Credentials),
                (null, not null) => new AmazonSecretsManagerClient(o.Region),
                _ => new AmazonSecretsManagerClient(),
            };

            IAwsSecretsManagerClient adapter = new AwsSecretsManagerClientAdapter(rawClient);
            return new AwsSecretsManagerPostQuantumKeyStore(adapter, o.SecretPrefix);
        });

        return services;
    }

    /// <summary>Convenience overload — defaults to AWS SDK's region/credential resolution.</summary>
    public static IServiceCollection AddPostQuantumDataProtectionAws(this IServiceCollection services)
        => services.AddPostQuantumDataProtectionAws(_ => { });
}
