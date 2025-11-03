using System;
using System.Linq;
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
        {
            _logger.LogWarning("Introspection rejected: no principal resolved for token {TokenId}. Stack: {Stack}", context.TokenId, Environment.StackTrace);
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "The token is no longer valid.");
            return;
        }

        // Machine-to-machine (client credentials) tokens are not session-bound.
        var subject = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(subject))
        {
            _logger.LogDebug("Introspection bypass: token {TokenId} has no subject. Claims: {Claims}", context.TokenId, string.Join(", ", principal.Claims.Select(c => $"{c.Type}={c.Value}")));
            return;
        }

        var sid = principal.GetClaim("sid");
        if (string.IsNullOrEmpty(sid))
        {
            var authorizationId = principal.GetAuthorizationId();
            if (!string.IsNullOrEmpty(authorizationId))
            {
                var resolved = await _sessions.GetActiveReferenceByAuthorizationIdAsync(authorizationId, context.CancellationToken);
                if (!string.IsNullOrEmpty(resolved))
                {
                    var activeViaAuthorization = await _sessions.IsActiveAsync(resolved, context.CancellationToken);
                    if (activeViaAuthorization)
                    {
                        _logger.LogInformation("Introspection fallback success: token {TokenId} resolved active sid {Sid} via authorization {AuthorizationId}.",
                            context.TokenId, resolved, authorizationId);
                        return;
                    }

                    _logger.LogInformation("Introspection rejected: authorization {AuthorizationId} is linked to inactive sid {Sid} for token {TokenId}. Stack: {Stack}",
                        authorizationId, resolved, context.TokenId, Environment.StackTrace);
                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidToken,
                        description: "The interactive session referenced by sid is no longer active.");
                    return;
                }
            }

            var claimsDump = string.Join(", ", principal.Claims.Select(c => $"{c.Type}={c.Value}"));
            _logger.LogWarning("Introspection rejected: token {TokenId} is missing sid for subject {Subject}. Claims: {Claims}. Stack: {Stack}",
                context.TokenId, subject, claimsDump, Environment.StackTrace);
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "The interactive session identifier (sid) is required.");
            return;
        }

        var active = await _sessions.IsActiveAsync(sid, context.CancellationToken);
        if (active)
        {
            _logger.LogDebug("Introspection accepted: sid {Sid} for token {TokenId} is active.", sid, context.TokenId);
            return;
        }

        _logger.LogInformation("Introspection rejected: sid {Sid} associated with token {TokenId} is inactive. Stack: {Stack}",
            sid, context.TokenId, Environment.StackTrace);
        context.Reject(
            error: OpenIddictConstants.Errors.InvalidToken,
            description: "The interactive session referenced by sid is no longer active.");
    }
}
