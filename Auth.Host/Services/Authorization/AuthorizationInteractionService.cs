// Auth.Host\Services\Authorization\AuthorizationInteractionService.cs
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Infrastructure;
using Auth.Host.ProfileService; // IOpenIddictProfileService
using Auth.Host.Services;
using Auth.Host.Services.Support;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Host.Services.Authorization;

public class AuthorizationInteractionService
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly CustomSignInManager _signInManager;
    private readonly UserManager<UserEntity> _userManager;
    private readonly IOpenIddictProfileService _profile;
    private readonly ISessionService _sessions;
    private readonly SessionBindingService _sessionBinder;
    private readonly ILogger<AuthorizationInteractionService> _logger;

    public AuthorizationInteractionService(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        CustomSignInManager signInManager,
        UserManager<UserEntity> userManager,
        IOpenIddictProfileService profile,
        ISessionService sessions,
        SessionBindingService sessionBinder,
        ILogger<AuthorizationInteractionService> logger)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _profile = profile;
        _sessions = sessions;
        _sessionBinder = sessionBinder;
        _logger = logger;
    }

    public async Task<IActionResult> HandleAuthorizeAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = httpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // If the browser has a sid cookie, ensure it is valid before attempting silent re-login.
        if (httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSidCookie))
        {
            if (SessionCookie.TryUnpack(rawSidCookie, out var reference, out var secret))
            {
                var stillValid = await _sessions.ValidateBrowserSessionAsync(reference, secret);
                if (stillValid is null)
                {
                    _logger.LogInformation("Discarding invalid sid cookie {Sid} during authorize pipeline.", reference);
                    DeleteSidCookie(httpContext, SameSiteMode.Lax);
                    await _signInManager.SignOutAsync();
                }
            }
            else
            {
                _logger.LogInformation("Deleting malformed sid cookie during authorize pipeline.");
                DeleteSidCookie(httpContext, SameSiteMode.Lax);
            }
        }

        // Если пользователь не залогинен - пробуем восстановить сессию по sid и только потом отправляем на логин
        var result = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded)
        {
            if (await TryRestoreIdentityFromSessionCookieAsync(httpContext))
            {
                _logger.LogInformation("Successfully restored authentication from session cookie for request {RequestId}.", httpContext.TraceIdentifier);
                result = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            }
        }

        if (!result.Succeeded)
        {
            // Если prompt=none, возвращаем ошибку без редиректа
            if (request.Prompt == "none")
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            // Сохраняем параметры запроса для возврата после логина
            var parameters = httpContext.Request.HasFormContentType ? [.. httpContext.Request.Form] : httpContext.Request.Query.ToList();

            return controller.Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpContext.Request.PathBase + httpContext.Request.Path + QueryString.Create(parameters)
                });
        }

        // Получаем пользователя
        // Silent-login guard via service
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
            return controller.Challenge(IdentityConstants.ApplicationScheme); // кука «плохая» — просим перелогиниться

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return controller.Challenge(IdentityConstants.ApplicationScheme); // пользователь удалён/изменён

        // Клиентское приложение
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Постоянные авторизации (если есть)
        var authorizations = new List<object>();
        await foreach (var authorization in _authorizationManager.FindAsync(
            subject: user.Id.ToString(),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()))
        {
            authorizations.Add(authorization);
        }

        // Evaluate consent policy for this client and branch accordingly.
        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        switch (consentType)
        {
            case ConsentTypes.External when !authorizations.Any():
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && request.Prompt != "consent":
                {
                    var principal = await _profile.CreateAsync(user, request);

                    // Create/attach server-side session (sid)
                    await _sessionBinder.AttachInteractiveSessionAsync(httpContext, principal, user, request.ClientId);
                    _logger.LogInformation("Attached interactive session for user {UserId} client {ClientId} via consent policy.", user.Id, request.ClientId);

                    var authId = await CreatePerSessionAuthorizationAsync(principal, user, application);
                    principal.SetAuthorizationId(authId);
                    // Link authorization to current DB session for cascade token revocation
                    var sidVal = principal.GetClaim("sid");
                    if (!string.IsNullOrEmpty(sidVal))
                        await _sessions.LinkAuthorizationAsync(sidVal, authId, request.ClientId);

                    return controller.SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

            case ConsentTypes.Explicit when request.Prompt == "none":
            case ConsentTypes.Systematic when request.Prompt == "none":
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }));

            default:
                {
                    // (Упрощённо) автоматически даём согласие
                    var consentPrincipal = await _profile.CreateAsync(user, request);

                    await _sessionBinder.AttachInteractiveSessionAsync(httpContext, consentPrincipal, user, request.ClientId);
                    _logger.LogInformation("Attached interactive session for user {UserId} client {ClientId} in default consent branch.", user.Id, request.ClientId);

                    var authId = await CreatePerSessionAuthorizationAsync(consentPrincipal, user, application);
                    consentPrincipal.SetAuthorizationId(authId);
                    // Link the current sid to the authorization for precise revocation later
                    var sidVal = consentPrincipal.GetClaim("sid");
                    if (!string.IsNullOrEmpty(sidVal))
                        await _sessions.LinkAuthorizationAsync(sidVal, authId, request.ClientId);

                    return controller.SignIn(consentPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
        }
    }

    public async Task<IActionResult> HandleTokenExchangeAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = httpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Извлекаем principal из authorization code/refresh token
            var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Пользователь
            var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject));
            if (user is null || !user.IsActive)
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            user is null ? "The token is no longer valid." : "The user is no longer allowed to sign in."
                    }));
            }

            var principal = await _profile.CreateAsync(user, request);

            // Carry over session id from the original grant (if any)
            var sid = result.Principal!.GetClaim("sid");
            // Also carry over authorization id from the original grant (bind tokens to same auth)
            var originalAuthId = result.Principal!.GetAuthorizationId();
            if (!string.IsNullOrEmpty(originalAuthId))
            {
                principal.SetAuthorizationId(originalAuthId);
                // Ensure session<->authorization link exists for reliable revocation
                if (!string.IsNullOrEmpty(sid))
                    await _sessions.LinkAuthorizationAsync(sid, originalAuthId, request.ClientId);
            }
            if (string.IsNullOrEmpty(sid))
            {
                // For refresh_token grant: session-bound is mandatory (block legacy RTs without sid)
                if (request.IsRefreshTokenGrantType())
                {
                    return controller.Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session context is missing."
                        }));
                }

                // For authorization_code grant: establish a new interactive session and stamp sid
                await _sessionBinder.AttachInteractiveSessionAsync(httpContext, principal, user, request.ClientId);
                _logger.LogInformation("Bound new interactive session for user {UserId} client {ClientId} during token exchange.", user.Id, request.ClientId);
            }
            else
            {
                var ci = (ClaimsIdentity)principal.Identity!;
                foreach (var existingSid in ci.FindAll("sid").ToArray())
                    ci.RemoveClaim(existingSid);

                var originalSidClaim = result.Principal!.Claims.FirstOrDefault(c => c.Type == "sid");
                var sidClaim = CloneClaim(originalSidClaim, "sid", sid);
                ci.AddClaim(sidClaim);
                // Ensure "sid" is emitted into id_token/access_token/refresh_token payloads
                sidClaim.SetDestinations(
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken,
                    "authorization_code",
                    "refresh_token");

                var persistedValue = result.Principal!.GetClaim(SessionClaimTypes.Persistence);
                var isPersistentSession = ParsePersistenceClaim(persistedValue);

                foreach (var existingPersistence in ci.FindAll(SessionClaimTypes.Persistence).ToArray())
                    ci.RemoveClaim(existingPersistence);

                var originalPersistenceClaim = result.Principal!.Claims.FirstOrDefault(c => c.Type == SessionClaimTypes.Persistence);
                var persistenceClaim = CloneClaim(originalPersistenceClaim, SessionClaimTypes.Persistence, isPersistentSession ? "true" : "false");
                ci.AddClaim(persistenceClaim);
                persistenceClaim.SetDestinations(
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken,
                    "authorization_code",
                    "refresh_token");

                if (isPersistentSession)
                {
                    var renewed = await _sessions.RefreshBrowserSecretAsync(sid, user.Id);
                    if (renewed is null)
                    {
                        return controller.Forbid(
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties(new Dictionary<string, string?>
                            {
                                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session has been revoked."
                            }));
                    }

                    httpContext.Response.Cookies.Append(
                        SessionCookie.Name,
                        SessionCookie.Pack(renewed.Value.ReferenceId, renewed.Value.BrowserSecret),
                        CreateSessionCookieOptions(CustomSignInManager.LongSessionLifetime));
                }
            }

            return controller.SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static Claim CloneClaim(Claim? source, string type, string value)
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

    public async Task<IActionResult> HandleUserInfoAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var claimsPrincipal = (await httpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        // Enforce session-bound access: deny if the session referenced by 'sid' is revoked
        var sid = claimsPrincipal!.GetClaim("sid");
        if (!string.IsNullOrEmpty(sid))
        {
            var active = await _sessions.IsActiveAsync(sid);
            if (!active)
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session has been revoked."
                    }));
            }
        }

        var user = await _userManager.FindByIdAsync(claimsPrincipal!.GetClaim(Claims.Subject));
        if (user is null)
        {
            return controller.Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id.ToString()
        };

        if (claimsPrincipal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.UserName ?? "";
            claims[Claims.PreferredUsername] = user.UserName ?? "";
            claims["full_name"] = user.FullName ?? "";
        }

        if (claimsPrincipal.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email ?? "";
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (claimsPrincipal.HasScope(Scopes.Phone))
        {
            claims[Claims.PhoneNumber] = user.PhoneNumber ?? "";
            claims[Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }

        // Also include roles so SPA can render privileges from userinfo
        var roles = await _userManager.GetRolesAsync(user);
        if (roles is not null && roles.Count > 0)
        {
            claims[Claims.Role] = roles.ToArray();
            claims[ClaimTypes.Role] = roles.ToArray();
            claims["roles"] = roles.ToArray();
        }

        return controller.Ok(claims);
    }

    public async Task<IActionResult> HandleLogoutAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = httpContext.GetOpenIddictServerRequest();

        // Try to revoke the DB session referenced by id_token_hint (sid)
        try
        {
            var oidc = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = oidc?.Principal;
            string? sid = principal?.GetClaim("sid");
            if (string.IsNullOrEmpty(sid) && httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSid) &&
                SessionCookie.TryUnpack(rawSid, out var reference, out _))
            {
                sid = reference;
            }
            if (!string.IsNullOrEmpty(sid))
            {
                var by = principal?.GetClaim(Claims.Subject) ?? httpContext.User?.FindFirstValue(Claims.Subject) ?? httpContext.User?.Identity?.Name;
                await _sessions.RevokeAsync(sid!, reason: "logout", by: by);
            }
        }
        catch
        {
            // Best-effort: don't block logout if revocation fails
        }

        // Clean up sid cookie regardless
        DeleteSidCookie(httpContext, SameSiteMode.Lax);

        await _signInManager.SignOutAsync();

        if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
        {
            return controller.SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = request.PostLogoutRedirectUri });
        }

        return controller.SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }

    /// <summary>
    /// OpenIddict does not expose session scoping out of the box.
    /// We mint a dedicated permanent authorization per interactive session so that revoking the session
    /// reliably tears down refresh/access tokens created through it.
    /// </summary>
    private async Task<string> CreatePerSessionAuthorizationAsync(ClaimsPrincipal principal, UserEntity user, object application)
    {
        var clientId = await _applicationManager.GetIdAsync(application)
            ?? throw new InvalidOperationException("Client identifier could not be resolved.");

        var authorization = await _authorizationManager.CreateAsync(
            principal: principal,
            subject: user.Id.ToString(),
            client: clientId,
            type: AuthorizationTypes.Permanent,
            scopes: principal.GetScopes());

        var authorizationId = await _authorizationManager.GetIdAsync(authorization);
        if (string.IsNullOrEmpty(authorizationId))
            throw new InvalidOperationException("Unable to resolve authorization id.");

        return authorizationId;
    }

    internal async Task<bool> TryRestoreIdentityFromSessionCookieAsync(HttpContext httpContext)
    {
        if (!httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSid) ||
            !SessionCookie.TryUnpack(rawSid, out var reference, out var secret))
        {
            return false;
        }

        var validation = await _sessions.ValidateBrowserSessionAsync(reference, secret, requireActive: true);
        if (validation is null)
        {
            _logger.LogWarning("Failed to validate sid {Sid} while restoring identity. Clearing cookie.", reference);
            DeleteSidCookie(httpContext, SameSiteMode.Lax);
            await _signInManager.SignOutAsync();
            return false;
        }

        var user = await _userManager.FindByIdAsync(validation.Value.UserId.ToString());
        if (user is null || !user.IsActive)
        {
            await _sessions.RevokeAsync(reference, reason: "user_missing_or_inactive");
            _logger.LogWarning("Revoked sid {Sid} because user {UserId} missing or inactive during restore.", reference, validation.Value.UserId);
            DeleteSidCookie(httpContext, SameSiteMode.Lax);
            return false;
        }

        var rememberMe = DeterminePersistence(validation.Value);
        await _signInManager.SignInWithSessionPolicyAsync(user, rememberMe);
        _logger.LogInformation("Restored identity from sid {Sid} for user {UserId}. RememberMe={RememberMe}", reference, user.Id, rememberMe);
        return true;
    }

    private static bool DeterminePersistence(SessionValidationResult validation)
    {
        if (validation.ExpiresAt is null) return true;
        var duration = validation.ExpiresAt.Value - validation.CreatedAt;
        return duration >= CustomSignInManager.LongSessionLifetime - TimeSpan.FromMinutes(1);
    }

    private static bool ParsePersistenceClaim(string? value)
        => bool.TryParse(value, out var parsed) ? parsed : true;

    private static CookieOptions CreateSessionCookieOptions(TimeSpan lifetime) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        IsEssential = true,
        Expires = DateTimeOffset.UtcNow.Add(lifetime)
    };

    private static void DeleteSidCookie(HttpContext httpContext, SameSiteMode sameSiteMode)
    {
        if (httpContext.Request.Cookies.ContainsKey(SessionCookie.Name))
        {
            httpContext.Response.Cookies.Delete(SessionCookie.Name, new CookieOptions
            {
                Secure = true,
                SameSite = sameSiteMode
            });
        }
    }
}
