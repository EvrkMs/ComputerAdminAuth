using Auth.Host.Services.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Server.AspNetCore;

namespace Auth.Host.Controllers;

[ApiController]
public sealed class AuthorizationController : ControllerBase
{
    private readonly AuthorizationInteractionService _authorization;

    public AuthorizationController(AuthorizationInteractionService authorization)
    {
        _authorization = authorization;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public Task<IActionResult> Authorize()
        => _authorization.HandleAuthorizeAsync(this);

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    public Task<IActionResult> Exchange()
        => _authorization.HandleTokenExchangeAsync(this);

    [HttpGet("~/connect/userinfo")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public Task<IActionResult> UserInfo()
        => _authorization.HandleUserInfoAsync(this);

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    [IgnoreAntiforgeryToken]
    public Task<IActionResult> Logout()
        => _authorization.HandleLogoutAsync(this);
}
