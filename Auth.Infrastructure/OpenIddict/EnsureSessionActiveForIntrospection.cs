using Auth.Application.Interfaces;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Auth.Infrastructure.OpenIddict;

/// <summary>
/// Ensures that tokens evaluated via the introspection endpoint are still linked to an active browser session.
/// If the session referenced by the <c>sid</c> claim is missing or revoked, the token is rejected.
/// </summary>
public sealed class EnsureSessionActiveForIntrospection
    : IOpenIddictServerHandler<OpenIddictServerEvents.HandleIntrospectionRequestContext>
{
    private readonly ISessionService _sessions;
    private readonly ILogger<EnsureSessionActiveForIntrospection> _logger;

    public EnsureSessionActiveForIntrospection(
        ISessionService sessions,
        ILogger<EnsureSessionActiveForIntrospection> logger)
    {
        _sessions = sessions;
        _logger = logger;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.HandleIntrospectionRequestContext context)
    {
        if (context is null)
            throw new ArgumentNullException(nameof(context));

        // Nothing to do if another handler already handled/skipped/rejected the request.
        if (context.IsRequestHandled || context.IsRequestSkipped || context.IsRejected)
            return;

        var principal = context.GenericTokenPrincipal;
        if (principal is null)
            return;

        // Machine-to-machine (client credentials) tokens are not session-bound.
        var subject = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(subject))
            return;

        var sid = principal.GetClaim("sid");
        if (string.IsNullOrEmpty(sid))
        {
            _logger.LogWarning("Introspection rejected: token {TokenId} is missing sid for subject {Subject}.", context.TokenId, subject);
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "The token is not bound to an active session.",
                uri: null);
            return;
        }

        var active = await _sessions.IsActiveAsync(sid, context.CancellationToken);
        if (active)
            return;

        _logger.LogInformation("Introspection rejected: sid {Sid} associated with token {TokenId} is inactive.", sid, context.TokenId);
        context.Reject(
            error: OpenIddictConstants.Errors.InvalidToken,
            description: "The session associated with this token is no longer active.",
            uri: null);
    }
}
