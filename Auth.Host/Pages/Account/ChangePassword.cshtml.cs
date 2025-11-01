using Auth.Domain.Entities;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace Auth.Host.Pages.Account
{
    [AllowAnonymous]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<UserEntity> _userManager;
        private readonly CustomSignInManager _signInManager;

        public ChangePasswordModel(
            UserManager<UserEntity> userManager,
            CustomSignInManager signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        // Параметры, приходящие в адресной строке
        [BindProperty(SupportsGet = true)]
        public string? UserName { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        [BindProperty(SupportsGet = true)]
        public bool RequireChange { get; set; }

        [BindProperty, Required(ErrorMessage = "Укажите текущий пароль")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

        [BindProperty, Required(ErrorMessage = "Укажите новый пароль")]
        [DataType(DataType.Password)]
        [StringLength(100, ErrorMessage = "Пароль должен быть не короче {2} символов.", MinimumLength = 6)]
        public string NewPassword { get; set; } = string.Empty;

        [BindProperty, Required(ErrorMessage = "Повторите новый пароль")]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "Пароли не совпадают")]
        public string ConfirmPassword { get; set; } = string.Empty;

        // GET
        public void OnGet() { }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            if (string.IsNullOrWhiteSpace(UserName))
            {
                ModelState.AddModelError(string.Empty, "Не указан пользователь.");
                return Page();
            }

            var user = await _userManager.FindByNameAsync(UserName);
            if (user is null || !user.IsActive)
            {
                ModelState.AddModelError(string.Empty, "Пользователь не найден или неактивен.");
                return Page();
            }

            // Проверяем текущий пароль отдельно
            var passwordOk = await _userManager.CheckPasswordAsync(user, CurrentPassword);
            if (!passwordOk)
            {
                ModelState.AddModelError(nameof(CurrentPassword), "Неверный текущий пароль.");
                return Page();
            }

            var change = await _userManager.ChangePasswordAsync(user, CurrentPassword, NewPassword);
            if (!change.Succeeded)
            {
                foreach (var e in change.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);
                return Page();
            }

            // Сбросим флаг MustChangePassword (если есть)
            var prop = user.GetType().GetProperty("MustChangePassword");
            if (prop is not null && prop.PropertyType == typeof(bool))
            {
                prop.SetValue(user, false);
                await _userManager.UpdateAsync(user);
            }

            // Перелогиним и отправим по безопасному ReturnUrl
            await _signInManager.SignInWithSessionPolicyAsync(user, rememberMe: false);
            var safeReturn = (!string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
                ? ReturnUrl!
                : "/";
            return LocalRedirect(safeReturn);
        }
    }
}
