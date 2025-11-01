using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Infrastructure;
using Auth.TelegramAuth.Interface; // ITelegramAuthService, TelegramRawData
using Auth.TelegramAuth.Raw;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Host.Pages.Account.Telegram
{
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class TelegramLoginModel : PageModel
    {
        private readonly ITelegramRepository _telegramRepo;
        private readonly UserManager<UserEntity> _userManager;
        private readonly CustomSignInManager _signInManager;
        private readonly ITelegramAuthService _tg;
        private readonly ILogger<TelegramLoginModel> _log;
        private readonly IUnitOfWork _unitOfWork;

        public TelegramLoginModel(
            ITelegramRepository telegramRepo,
            UserManager<UserEntity> userManager,
            CustomSignInManager signInManager,
            ITelegramAuthService tg,
            ILogger<TelegramLoginModel> log,
            IUnitOfWork unitOfWork)
        {
            _telegramRepo = telegramRepo;
            _userManager = userManager;
            _signInManager = signInManager;
            _tg = tg;
            _log = log;
            _unitOfWork = unitOfWork;
        }

        public class TelegramQuery
        {
            [FromQuery(Name = "id")] public long Id { get; set; }
            [FromQuery(Name = "username")] public string? Username { get; set; }
            [FromQuery(Name = "first_name")] public string? FirstName { get; set; }
            [FromQuery(Name = "last_name")] public string? LastName { get; set; }
            [FromQuery(Name = "photo_url")] public string? PhotoUrl { get; set; }
            [FromQuery(Name = "auth_date")] public long AuthDate { get; set; }
            [FromQuery(Name = "hash")] public string Hash { get; set; } = string.Empty;
            [FromQuery(Name = "returnUrl")] public string? ReturnUrl { get; set; }
        }

        public async Task<IActionResult> OnGetAsync([FromQuery] TelegramQuery q, CancellationToken ct)
        {
            // If page is opened directly (no Telegram params), render the page with the widget.
            if (q.Id == 0 && q.AuthDate == 0 && string.IsNullOrWhiteSpace(q.Hash))
            {
                return Page();
            }
            // 1) Проверка обязательных полей
            if (q.Id <= 0 || q.AuthDate <= 0 || string.IsNullOrWhiteSpace(q.Hash))
            {
                _log.LogWarning("TelegramLogin: missing fields (id={id}, auth_date={auth}, hash?={hash})",
                    q.Id, q.AuthDate, !string.IsNullOrEmpty(q.Hash));
                return RedirectToPage("/Account/Login", new { returnUrl = q.ReturnUrl, error = "missing_fields" });
            }

            // 2) Восстановим сырые данные + проверим TTL и подпись
            var raw = new TelegramRawData()
            {
                Id = q.Id,
                Username = q.Username,
                FirstName = q.FirstName,
                LastName = q.LastName,
                PhotoUrl = q.PhotoUrl,
                AuthDate = q.AuthDate,
                Hash = q.Hash
            };

            if (!_tg.VerifyWidget(raw, out var sigErr))
            {
                _log.LogWarning("TelegramLogin: bad signature (id={id}, err={err})", q.Id, sigErr ?? "-");
                return RedirectToPage("/Account/Login", new { returnUrl = q.ReturnUrl, error = sigErr ?? "invalid_signature" });
            }

            // 3) Найдём привязку к учётной записи
            var telegram = await _telegramRepo.GetByTelegramIdAsync(q.Id, ct);
            if (telegram == null)
            {
                _log.LogWarning("TelegramLogin: no binding for telegram_id={id}", q.Id);
                return RedirectToPage("/Account/Login", new { returnUrl = q.ReturnUrl, error = "no_binding" });
            }

            // 4) Пользователь
            var user = await _userManager.FindByIdAsync(telegram.UserId.ToString());
            if (user == null)
            {
                _log.LogWarning("TelegramLogin: user not found for id={userId}", telegram.UserId);
                return RedirectToPage("/Account/Login", new { returnUrl = q.ReturnUrl, error = "user_not_found" });
            }

            if (!user.IsActive)
            {
                _log.LogWarning("TelegramLogin: user {userId} is not active", user.Id);
                return RedirectToPage("/Account/Login", new { returnUrl = q.ReturnUrl, error = "user_inactive" });
            }

            if (user.MustChangePassword)
            {
                _log.LogInformation("TelegramLogin: user {userId} must change password", user.Id);
                return RedirectToPage("/Account/ChangePassword", new
                {
                    userName = user.UserName,
                    returnUrl = SafeReturn(q.ReturnUrl),
                    requireChange = true
                });
            }

            // 5) Обновим дату последнего входа
            telegram.LastLoginDate = DateTime.UtcNow;
            await _telegramRepo.UpdateAsync(telegram, ct);
            await _unitOfWork.SaveChangesAsync(ct);

            // 6) Вход
            await _signInManager.SignInWithSessionPolicyAsync(user, rememberMe: true);

            var targetUrl = SafeReturn(q.ReturnUrl);
            _log.LogInformation("TelegramLogin: success for user {userId}, redirecting to {url}", user.Id, targetUrl);
            return LocalRedirect(targetUrl);
        }

        private string SafeReturn(string? url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "/";
            if (!Url.IsLocalUrl(url)) return "/";
            return url;
        }
    }
}
