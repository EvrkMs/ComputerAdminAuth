using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace Auth.Host.Services.Authorization.Handlers;

public sealed class UserInfoRequestHandler
{
    private readonly ISessionService _sessions;
    private readonly UserManager<UserEntity> _userManager;

    public UserInfoRequestHandler(ISessionService sessions, UserManager<UserEntity> userManager)
    {
        _sessions = sessions;
        _userManager = userManager;
    }

    public async Task<IActionResult> HandleAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var claimsPrincipal = (await httpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

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
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session has been revoked."
                    }));
            }
        }

        var user = await _userManager.FindByIdAsync(claimsPrincipal!.GetClaim(OpenIddictConstants.Claims.Subject));
        if (user is null)
        {
            return controller.Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Subject] = user.Id.ToString()
        };

        if (claimsPrincipal.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            claims[OpenIddictConstants.Claims.Name] = user.UserName ?? "";
            claims[OpenIddictConstants.Claims.PreferredUsername] = user.UserName ?? "";
            claims["full_name"] = user.FullName ?? "";
        }

        if (claimsPrincipal.HasScope(OpenIddictConstants.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = user.Email ?? "";
            claims[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (claimsPrincipal.HasScope(OpenIddictConstants.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = user.PhoneNumber ?? "";
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }

        var roles = await _userManager.GetRolesAsync(user);
        if (roles is not null && roles.Count > 0)
        {
            claims[OpenIddictConstants.Claims.Role] = roles.ToArray();
            claims[ClaimTypes.Role] = roles.ToArray();
            claims["roles"] = roles.ToArray();
        }

        return controller.Ok(claims);
    }
}
