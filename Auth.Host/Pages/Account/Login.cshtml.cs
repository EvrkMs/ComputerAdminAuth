using Auth.Infrastructure; // CustomSignInManager
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.OutputCaching;
using System.ComponentModel.DataAnnotations;

namespace Auth.Host.Pages.Account
{
    [OutputCache(PolicyName = "AnonRazor")] // Кешируем GET для анонимных пользователей
    public class LoginModel : PageModel
    {
        private readonly CustomSignInManager _signInManager;

        public LoginModel(CustomSignInManager signInManager)
        {
            _signInManager = signInManager;
        }

        [BindProperty, Required(ErrorMessage = "Укажите имя пользователя")]
        public string UserName { get; set; } = string.Empty;

        [BindProperty, Required(ErrorMessage = "Укажите пароль")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [BindProperty]
        public bool RememberMe { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        // GET
        public void OnGet() { }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var result = await _signInManager.PasswordSignInAsync(
                UserName, Password, RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                var target = SafeReturnUrlOrRoot(ReturnUrl);
                return LocalRedirect(target);
            }

            if (result.RequiresTwoFactor)
            {
                ModelState.AddModelError(string.Empty, "Требуется двухфакторная аутентификация.");
                return Page();
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Пользователь временно заблокирован из-за неудачных попыток.");
                return Page();
            }

            if (result.IsNotAllowed)
            {
                // Требуется смена пароля: перенаправим на страницу ChangePassword
                var safeReturn = SafeReturnUrlOrRoot(ReturnUrl);
                return RedirectToPage("/Account/ChangePassword", new
                {
                    userName = UserName,
                    returnUrl = safeReturn,
                    requireChange = true
                });
            }

            ModelState.AddModelError(string.Empty, "Неверное имя пользователя или пароль");
            return Page();
        }

        private string SafeReturnUrlOrRoot(string? url)
            => (!string.IsNullOrWhiteSpace(url) && Url.IsLocalUrl(url)) ? url! : "/";
    }
}

