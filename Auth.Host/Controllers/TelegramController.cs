using Auth.Application.UseCases.Telegram;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

namespace Auth.Host.Controllers;

[ApiController]
[Route("api/telegram")]
[IgnoreAntiforgeryToken]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = "ApiRead")]
public class TelegramController : ControllerBase
{
    private readonly UnbindTelegramCommand _unbindTelegram;
    private readonly GetMyTelegramQuery _getMyTelegram;
    private readonly ILogger<TelegramController> _logger;

    public TelegramController(
        UnbindTelegramCommand unbindTelegram,
        GetMyTelegramQuery getMyTelegram,
        ILogger<TelegramController> logger)
    {
        _unbindTelegram = unbindTelegram;
        _getMyTelegram = getMyTelegram;
        _logger = logger;
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        // Попробуем разные способы получить userId
        var sub = User.FindFirstValue("sub")
            ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? User.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        _logger.LogDebug("Looking for subject claim. Found: {sub}", sub);
        _logger.LogDebug("All claims: {claims}",
            string.Join(", ", User.Claims.Select(c => $"{c.Type}={c.Value}")));

        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new
            {
                error = "no_subject",
                claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
            });
        }

        if (!Guid.TryParse(sub, out var userId))
        {
            return Unauthorized(new
            {
                error = "invalid_subject",
                subject = sub
            });
        }

        var tg = await _getMyTelegram.ExecuteAsync(userId, ct);
        return tg is null ? NotFound(new { error = "no_telegram_binding" }) : Ok(tg);
    }

    [HttpPost("unbind")]
    [Authorize(Policy = "ApiWrite")]
    public async Task<IActionResult> Unbind(CancellationToken ct)
    {
        var sub = User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(sub))
            return Unauthorized("no subject in token");

        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized("invalid subject");

        var result = await _unbindTelegram.ExecuteAsync(userId, ct);
        return result.Success
            ? Ok(new { message = "unbound" })
            : NotFound(result.Error);
    }
}
