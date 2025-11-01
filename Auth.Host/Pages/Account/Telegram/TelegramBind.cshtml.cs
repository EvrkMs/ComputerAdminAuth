using Auth.Application.Interfaces;
using Auth.Application.UseCases.Telegram;
using Auth.Domain.Entities;
using Auth.TelegramAuth.Raw;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Host.Pages.Account.Telegram;

[Authorize]
public class TelegramBindModel : PageModel
{
    private const string ConfirmationPurpose = "telegram_bind";

    private readonly BindTelegramCommand _bindTelegram;
    private readonly UserManager<UserEntity> _userManager;
    private readonly IPasswordConfirmationService _passwordConfirmation;

    public TelegramBindModel(
        BindTelegramCommand bindTelegram,
        UserManager<UserEntity> userManager,
        IPasswordConfirmationService passwordConfirmation)
    {
        _bindTelegram = bindTelegram;
        _userManager = userManager;
        _passwordConfirmation = passwordConfirmation;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Error { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Message { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ConfirmationToken { get; set; }

    public void OnGet()
    {
        ReturnUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;
    }

    // GET из Telegram Login Widget
    public async Task<IActionResult> OnGetVerifyAsync(
        string id, string first_name, string last_name, string username,
        string photo_url, long auth_date, string hash, string confirmationToken, string? returnUrl, CancellationToken ct)
    {
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null)
        {
            return RedirectToPage("/Account/Login", new
            {
                returnUrl = Url.Page("/Account/Telegram/TelegramBind", new { returnUrl = returnUrl ?? "/" }),
                error = "not_authenticated"
            });
        }

        if (!currentUser.IsActive)
        {
            return RedirectToPage("/Account/Telegram/TelegramBind", new
            {
                returnUrl = returnUrl,
                error = "Аккаунт пользователя неактивен"
            });
        }

        var tokenValid = await _passwordConfirmation.ValidateTokenAsync(currentUser.Id, ConfirmationPurpose, confirmationToken, ct);
        if (!tokenValid)
        {
            return RedirectToPage("/Account/Telegram/TelegramBind", new
            {
                returnUrl = returnUrl,
                error = "Нужно подтвердить пароль перед привязкой Telegram"
            });
        }

        var dto = new TelegramRawData()
        {
            Id = long.Parse(id),
            Username = username,
            FirstName = first_name,
            LastName = last_name,
            PhotoUrl = photo_url,
            AuthDate = auth_date,
            Hash = hash
        };

        // Проверка подписи/срока делается внутри ITelegramAuthService с BotToken
        var result = await _bindTelegram.ExecuteAsync(currentUser.Id, dto, ct);

        if (result.Success)
        {
            return RedirectToPage("/Account/Telegram/TelegramBind", new
            {
                returnUrl = returnUrl,
                message = "Telegram успешно привязан!"
            });
        }

        return RedirectToPage("/Account/Telegram/TelegramBind", new
        {
            returnUrl = returnUrl,
            error = result.Error ?? "Не удалось привязать Telegram"
        });
    }
}
