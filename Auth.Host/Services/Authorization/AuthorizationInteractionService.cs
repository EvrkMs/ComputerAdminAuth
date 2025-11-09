using Auth.Host.Services.Authorization.Handlers;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Host.Services.Authorization;

public class AuthorizationInteractionService
{
    private readonly AuthorizeRequestHandler _authorizeHandler;
    private readonly TokenExchangeHandler _tokenHandler;
    private readonly UserInfoRequestHandler _userInfoHandler;
    private readonly LogoutRequestHandler _logoutHandler;

    public AuthorizationInteractionService(
        AuthorizeRequestHandler authorizeHandler,
        TokenExchangeHandler tokenHandler,
        UserInfoRequestHandler userInfoHandler,
        LogoutRequestHandler logoutHandler)
    {
        _authorizeHandler = authorizeHandler;
        _tokenHandler = tokenHandler;
        _userInfoHandler = userInfoHandler;
        _logoutHandler = logoutHandler;
    }

    public Task<IActionResult> HandleAuthorizeAsync(ControllerBase controller)
        => _authorizeHandler.HandleAsync(controller);

    public Task<IActionResult> HandleTokenExchangeAsync(ControllerBase controller)
        => _tokenHandler.HandleAsync(controller);

    public Task<IActionResult> HandleUserInfoAsync(ControllerBase controller)
        => _userInfoHandler.HandleAsync(controller);

    public Task<IActionResult> HandleLogoutAsync(ControllerBase controller)
        => _logoutHandler.HandleAsync(controller);
}
