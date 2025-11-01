using System.Text.Json;

namespace Auth.TokenValidation.Models;

/// <summary>
/// Result of an introspection call against auth service.
/// </summary>
public sealed record TokenIntrospectionResult
{
    public bool Active { get; init; }
    public string? Subject { get; init; }
    public string? ClientId { get; init; }
    public string? Username { get; init; }
    public string? Issuer { get; init; }
    public string? TokenType { get; init; }
    public string? TokenId { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? IssuedAt { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Audiences { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Raw extension data returned by the introspection endpoint (e.g. custom claims).
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement> Raw { get; init; } =
        new Dictionary<string, JsonElement>();
}
