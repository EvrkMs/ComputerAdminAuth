using System.ComponentModel.DataAnnotations;

namespace Auth.TokenValidation.Options;

/// <summary>
/// Configuration required to introspect opaque access tokens issued by Auth.Service.
/// </summary>
public sealed class AuthIntrospectionOptions
{
    /// <summary>
    /// Base authority (e.g. https://auth.ava-kk.ru). Must be absolute when <see cref="IntrospectionEndpoint"/> is relative.
    /// </summary>
    [Url]
    public string Authority { get; set; } = "https://auth.ava-kk.ru";

    /// <summary>
    /// Introspection endpoint relative to the authority or an absolute URL. Defaults to /connect/introspect.
    /// </summary>
    public string IntrospectionEndpoint { get; set; } = "/connect/introspect";

    /// <summary>
    /// Client identifier registered in auth service with introspection permission.
    /// </summary>
    [Required]
    public string ClientId { get; set; } = "svc.introspector";

    /// <summary>
    /// Client secret paired with <see cref="ClientId"/>.
    /// </summary>
    [Required]
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Optional token type hint to send to the introspection endpoint. Defaults to "access_token".
    /// </summary>
    public string TokenTypeHint { get; set; } = "access_token";

    internal Uri ResolveEndpoint()
    {
        if (Uri.TryCreate(IntrospectionEndpoint, UriKind.Absolute, out var absolute))
        {
            return absolute;
        }

        if (string.IsNullOrWhiteSpace(Authority))
        {
            throw new InvalidOperationException("Authority must be set when IntrospectionEndpoint is relative.");
        }

        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri))
        {
            throw new InvalidOperationException("Authority must be an absolute URI.");
        }

        return new Uri(authorityUri, IntrospectionEndpoint);
    }
}
