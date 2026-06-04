using Amazon;
using Amazon.Runtime;

namespace PostQuantum.DataProtection.Aws;

/// <summary>
/// Configuration for the AWS Secrets Manager-backed PQ key store.
/// </summary>
public sealed class AwsDataProtectionOptions
{
    /// <summary>
    /// AWS region the Secrets Manager client should target. When null, the SDK's default region
    /// resolver is used (environment, instance metadata, etc.).
    /// </summary>
    public RegionEndpoint? Region { get; set; }

    /// <summary>
    /// AWS credentials. When null, the SDK falls back to its default credential chain (env vars,
    /// shared credentials file, EC2 instance profile, ECS task role, etc.).
    /// </summary>
    public AWSCredentials? Credentials { get; set; }

    /// <summary>
    /// Secret-name prefix to use. Defaults to <see cref="AwsSecretsManagerPostQuantumKeyStore.DefaultSecretPrefix"/>.
    /// </summary>
    public string SecretPrefix { get; set; } = AwsSecretsManagerPostQuantumKeyStore.DefaultSecretPrefix;
}
