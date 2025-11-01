using Auth.TokenValidation.Models;

namespace Auth.TokenValidation;

public interface ITokenIntrospector
{
    /// <summary>
    /// Calls auth service introspection endpoint and returns the parsed response.
    /// </summary>
    Task<TokenIntrospectionResult> IntrospectAsync(string token, CancellationToken cancellationToken = default);
}
