using Auth.Domain.Entities;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace Auth.Host.Services.Authorization.Handlers;

internal static class AuthorizationHandlerUtilities
{
    public static async Task<string> CreatePerSessionAuthorizationAsync(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager,
        ClaimsPrincipal principal,
        UserEntity user,
        object application)
    {
        var clientId = await applicationManager.GetIdAsync(application)
            ?? throw new InvalidOperationException("Client identifier could not be resolved.");

        var authorization = await authorizationManager.CreateAsync(
            principal: principal,
            subject: user.Id.ToString(),
            client: clientId,
            type: AuthorizationTypes.Permanent,
            scopes: principal.GetScopes());

        var authorizationId = await authorizationManager.GetIdAsync(authorization);
        if (string.IsNullOrEmpty(authorizationId))
            throw new InvalidOperationException("Unable to resolve authorization id.");

        return authorizationId;
    }

    public static Claim CloneClaim(Claim? source, string type, string value)
    {
        if (source is null)
            return new Claim(type, value);

        var clone = new Claim(source.Type, value, source.ValueType, source.Issuer, source.OriginalIssuer);
        foreach (var kvp in source.Properties)
        {
            clone.Properties[kvp.Key] = kvp.Value;
        }
        return clone;
    }
}
