using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Auth.TokenValidation.Internal;
using Auth.TokenValidation.Models;
using Auth.TokenValidation.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.TokenValidation;

public sealed class TokenIntrospector : ITokenIntrospector
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly IOptionsMonitor<AuthIntrospectionOptions> _optionsMonitor;
    private readonly ILogger<TokenIntrospector>? _logger;

    public TokenIntrospector(
        HttpClient httpClient,
        IOptionsMonitor<AuthIntrospectionOptions> optionsMonitor,
        ILogger<TokenIntrospector>? logger = null)
    {
        _httpClient = httpClient;
        _optionsMonitor = optionsMonitor;
        _logger = logger;
    }

    public async Task<TokenIntrospectionResult> IntrospectAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("Token must be provided.", nameof(token));
        }

        var options = _optionsMonitor.CurrentValue ?? throw new InvalidOperationException("Auth introspection options are not configured.");

        if (string.IsNullOrWhiteSpace(options.ClientId) || string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            throw new InvalidOperationException("ClientId and ClientSecret must be configured for token introspection.");
        }

        var endpoint = options.ResolveEndpoint();
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);

        var payload = new Dictionary<string, string>
        {
            ["token"] = token
        };

        if (!string.IsNullOrWhiteSpace(options.TokenTypeHint))
        {
            payload["token_type_hint"] = options.TokenTypeHint;
        }

        request.Content = new FormUrlEncodedContent(payload);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = CreateBasicAuthHeader(options.ClientId, options.ClientSecret);

        try
        {
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new InvalidOperationException("Introspection rejected with 401 Unauthorized. Verify client credentials.");
            }

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new InvalidOperationException("Introspection rejected with 403 Forbidden. Verify client permissions.");
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await ReadSnippetAsync(response, cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException($"Introspection request failed with status {(int)response.StatusCode} ({response.ReasonPhrase}). Payload snippet: {errorBody}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var body = await JsonSerializer.DeserializeAsync<IntrospectionResponse>(stream, SerializerOptions, cancellationToken).ConfigureAwait(false);
            if (body is null)
            {
                throw new InvalidOperationException("Introspection response body was empty.");
            }

            return Map(body);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger?.LogError(ex, "Failed to reach auth introspection endpoint {Endpoint}", endpoint);
            throw new InvalidOperationException($"Failed to reach auth introspection endpoint {endpoint}", ex);
        }
    }

    private static AuthenticationHeaderValue CreateBasicAuthHeader(string clientId, string clientSecret)
    {
        var raw = $"{clientId}:{clientSecret}";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
        return new AuthenticationHeaderValue("Basic", encoded);
    }

    private static async Task<string> ReadSnippetAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        const int limit = 256;
        if (body.Length <= limit)
        {
            return body;
        }

        return body[..limit] + "...";
    }

    private static TokenIntrospectionResult Map(IntrospectionResponse response)
    {
        var scopes = string.IsNullOrWhiteSpace(response.Scope)
            ? Array.Empty<string>()
            : response.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var audiences = ExtractAudiences(response.Audience);

        return new TokenIntrospectionResult
        {
            Active = response.Active,
            Subject = response.Subject,
            ClientId = response.ClientId,
            Username = response.Username,
            Issuer = response.Issuer,
            TokenType = response.TokenType,
            TokenId = response.TokenId,
            ExpiresAt = ToDateTime(response.ExpiresAtEpoch),
            IssuedAt = ToDateTime(response.IssuedAtEpoch),
            NotBefore = ToDateTime(response.NotBeforeEpoch),
            Scopes = scopes,
            Audiences = audiences,
            Raw = response.AdditionalData
        };
    }

    private static DateTimeOffset? ToDateTime(long? epochSeconds)
    {
        if (epochSeconds is null)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(epochSeconds.Value);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ExtractAudiences(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    list.Add(item.GetString()!);
                }
            }
            return list;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return [element.GetString()!];
        }

        return Array.Empty<string>();
    }
}
