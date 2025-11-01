using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Host.Pages.Account.Telegram;

[Authorize]
public class ConfirmModel : PageModel
{
    private const string ConfirmationPurpose = "telegram_bind";

    private readonly UserManager<UserEntity> _userManager;
    private readonly IPasswordConfirmationService _passwordConfirmation;

    public ConfirmModel(
        UserManager<UserEntity> userManager,
        IPasswordConfirmationService passwordConfirmation)
    {
        _userManager = userManager;
        _passwordConfirmation = passwordConfirmation;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    public string Password { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
        ReturnUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        ReturnUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null)
        {
            return RedirectToPage("/Account/Login", new
            {
                returnUrl = Url.Page("/Account/Telegram/Confirm", new { returnUrl = ReturnUrl }),
                error = "not_authenticated"
            });
        }

        if (!currentUser.IsActive)
        {
            ErrorMessage = "Аккаунт пользователя неактивен";
            return Page();
        }

        var passwordOk = await _userManager.CheckPasswordAsync(currentUser, Password);
        if (!passwordOk)
        {
            ModelState.AddModelError(nameof(Password), "Неверный пароль");
            Password = string.Empty;
            return Page();
        }

        var token = await _passwordConfirmation.CreateTokenAsync(currentUser.Id, ConfirmationPurpose, ct);
        return RedirectToPage("/Account/Telegram/TelegramBind", new
        {
            returnUrl = ReturnUrl,
            confirmationToken = token
        });
    }
}
