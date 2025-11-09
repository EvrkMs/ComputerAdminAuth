using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Auth.Host.Services.Authorization;

internal static class OpenIddictRequestAccessor
{
    public static OpenIddictRequest GetRequiredRequest(HttpContext context)
    {
        var transaction = context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
        return transaction?.Request
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
    }
}
