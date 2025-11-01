namespace Auth.Host.Services.Support;

/// <summary>
/// Helpers for serializing/deserializing the secure sid cookie value.
/// The cookie never exposes raw session identifiers - it carries a reference id + secret pair.
/// </summary>
public static class SessionCookie
{
    public const string Name = "sid";

    public static string Pack(string referenceId, string secret)
        => $"{referenceId}.{secret}";

    public static bool TryUnpack(string? value, out string referenceId, out string secret)
    {
        referenceId = string.Empty;
        secret = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var separatorIndex = value.IndexOf('.');
        if (separatorIndex <= 0 || separatorIndex >= value.Length - 1)
            return false;

        referenceId = value[..separatorIndex];
        secret = value[(separatorIndex + 1)..];
        return !string.IsNullOrWhiteSpace(referenceId) && !string.IsNullOrWhiteSpace(secret);
    }
}
