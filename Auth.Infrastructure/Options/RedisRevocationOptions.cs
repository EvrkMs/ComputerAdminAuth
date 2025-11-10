namespace Auth.Infrastructure.Options;

public sealed class RedisRevocationOptions
{
    public string? ConnectionString { get; set; }
    public string ChannelName { get; set; } = "revoked_tokens";
}
