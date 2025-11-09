using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace Auth.Host.Services.Authorization.Handlers;

public sealed class AuthorizeRequestHandler
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly CustomSignInManager _signInManager;
    private readonly UserManager<UserEntity> _userManager;
    private readonly IOpenIddictProfileService _profile;
    private readonly ISessionService _sessions;
    private readonly SessionBindingService _sessionBinder;
    private readonly SessionCookieWorkflow _cookieWorkflow;
    private readonly ILogger<AuthorizeRequestHandler> _logger;

    public AuthorizeRequestHandler(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        CustomSignInManager signInManager,
        UserManager<UserEntity> userManager,
        IOpenIddictProfileService profile,
        ISessionService sessions,
        SessionBindingService sessionBinder,
        SessionCookieWorkflow cookieWorkflow,
        ILogger<AuthorizeRequestHandler> logger)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _profile = profile;
        _sessions = sessions;
        _sessionBinder = sessionBinder;
        _cookieWorkflow = cookieWorkflow;
        _logger = logger;
    }

    public async Task<IActionResult> HandleAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = httpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        await ValidateSidCookieAsync(httpContext);

        var result = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded)
        {
            if (await _cookieWorkflow.TryRestoreIdentityAsync(httpContext))
            {
                _logger.LogInformation("Successfully restored authentication from session cookie for request {RequestId}.", httpContext.TraceIdentifier);
                result = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            }
        }

        if (!result.Succeeded)
        {
            if (request.Prompt == "none")
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            var parameters = httpContext.Request.HasFormContentType ? [.. httpContext.Request.Form] : httpContext.Request.Query.ToList();

            return controller.Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpContext.Request.PathBase + httpContext.Request.Path + QueryString.Create(parameters)
                });
        }

        var guard = await _sessionBinder.EnforceCookieSessionOrChallengeAsync(httpContext, request);
        if (!guard.Ok) return guard.Action!;

        var userId = _userManager.GetUserId(result.Principal);
        if (string.IsNullOrEmpty(userId))
            userId = result.Principal.FindFirstValue(OpenIddictConstants.Claims.Subject);

        if (string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(result.Principal.Identity?.Name))
        {
            var byName = await _userManager.FindByNameAsync(result.Principal.Identity!.Name!);
            if (byName is not null) userId = byName.Id.ToString();
        }

        if (string.IsNullOrEmpty(userId))
            return controller.Challenge(IdentityConstants.ApplicationScheme);

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return controller.Challenge(IdentityConstants.ApplicationScheme);

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        var authorizations = new List<object>();
        await foreach (var authorization in _authorizationManager.FindAsync(
                   subject: user.Id.ToString(),
                   client: await _applicationManager.GetIdAsync(application),
                   status: OpenIddictConstants.Statuses.Valid,
                   type: OpenIddictConstants.AuthorizationTypes.Permanent,
                   scopes: request.GetScopes()))
        {
            authorizations.Add(authorization);
        }

        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        switch (consentType)
        {
            case OpenIddictConstants.ConsentTypes.External when !authorizations.Any():
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            case OpenIddictConstants.ConsentTypes.Implicit:
            case OpenIddictConstants.ConsentTypes.External when authorizations.Any():
            case OpenIddictConstants.ConsentTypes.Explicit when authorizations.Any() && request.Prompt != "consent":
                {
                    var principal = await _profile.CreateAsync(user, request);

                    await _sessionBinder.AttachInteractiveSessionAsync(httpContext, principal, user, request.ClientId);
                    _logger.LogInformation("Attached interactive session for user {UserId} client {ClientId} via consent policy.", user.Id, request.ClientId);

                    var authId = await AuthorizationHandlerUtilities.CreatePerSessionAuthorizationAsync(_authorizationManager, _applicationManager, principal, user, application);
                    principal.SetAuthorizationId(authId);

                    var sidVal = principal.GetClaim("sid");
                    if (!string.IsNullOrEmpty(sidVal))
                        await _sessions.LinkAuthorizationAsync(sidVal, authId, request.ClientId);

                    return controller.SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

            case OpenIddictConstants.ConsentTypes.Explicit when request.Prompt == "none":
            case OpenIddictConstants.ConsentTypes.Systematic when request.Prompt == "none":
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }));

            default:
                {
                    var principal = await _profile.CreateAsync(user, request);

                    await _sessionBinder.AttachInteractiveSessionAsync(httpContext, principal, user, request.ClientId);
                    _logger.LogInformation("Attached interactive session for user {UserId} client {ClientId} in default consent branch.", user.Id, request.ClientId);

                    var authId = await AuthorizationHandlerUtilities.CreatePerSessionAuthorizationAsync(_authorizationManager, _applicationManager, principal, user, application);
                    principal.SetAuthorizationId(authId);

                    var sidVal = principal.GetClaim("sid");
                    if (!string.IsNullOrEmpty(sidVal))
                        await _sessions.LinkAuthorizationAsync(sidVal, authId, request.ClientId);

                    return controller.SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
        }
    }

    private async Task ValidateSidCookieAsync(HttpContext httpContext)
    {
        if (!httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSidCookie))
            return;

        if (SessionCookie.TryUnpack(rawSidCookie, out var reference, out var secret))
        {
            var stillValid = await _sessions.ValidateBrowserSessionAsync(reference, secret);
            if (stillValid is null)
            {
                _logger.LogInformation("Discarding invalid sid cookie {Sid} during authorize pipeline.", reference);
                _cookieWorkflow.DeleteCookie(httpContext);
                await _signInManager.SignOutAsync();
            }
        }
        else
        {
            _logger.LogInformation("Deleting malformed sid cookie during authorize pipeline.");
            _cookieWorkflow.DeleteCookie(httpContext);
        }
    }
}
