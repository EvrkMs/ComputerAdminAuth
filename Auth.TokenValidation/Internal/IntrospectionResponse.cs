using System.Text.Json;
using System.Text.Json.Serialization;

namespace Auth.TokenValidation.Internal;

internal sealed class IntrospectionResponse
{
    [JsonPropertyName("active")]
    public bool Active { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("exp")]
    public long? ExpiresAtEpoch { get; init; }

    [JsonPropertyName("iat")]
    public long? IssuedAtEpoch { get; init; }

    [JsonPropertyName("nbf")]
    public long? NotBeforeEpoch { get; init; }

    [JsonPropertyName("sub")]
    public string? Subject { get; init; }

    [JsonPropertyName("aud")]
    public JsonElement Audience { get; init; }

    [JsonPropertyName("iss")]
    public string? Issuer { get; init; }

    [JsonPropertyName("jti")]
    public string? TokenId { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement> AdditionalData { get; init; } = new(StringComparer.Ordinal);
}
