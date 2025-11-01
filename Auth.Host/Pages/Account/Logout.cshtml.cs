using Auth.Application.Interfaces;
using Auth.Host.Services.Support;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace Auth.Host.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly ISessionService _sessions;

        public LogoutModel(ISessionService sessions)
        {
            _sessions = sessions;
        }
        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        public bool AutomaticRedirectAfterSignOut => true;

        public void OnGet()
        {
            // РџРѕРґРґРµСЂР¶РєР° post_logout_redirect_uri РёР· OIDC-Р·Р°РїСЂРѕСЃР°
            var request = HttpContext.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
            {
                ViewData["PostLogoutRedirectUri"] = request.PostLogoutRedirectUri;
            }
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            // Best-effort revoke of current session (sid from id_token_hint)
            try
            {
                var oidc = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                var principal = oidc?.Principal;
                var sid = principal?.FindFirst("sid")?.Value;
                if (string.IsNullOrEmpty(sid) && Request.Cookies.TryGetValue(SessionCookie.Name, out var raw) &&
                    SessionCookie.TryUnpack(raw, out var reference, out _))
                {
                    sid = reference;
                }
                if (!string.IsNullOrEmpty(sid))
                {
                    var by = principal?.FindFirst("sub")?.Value ?? User?.Identity?.Name;
                    await _sessions.RevokeAsync(sid!, reason: "logout", by: by);
                }
            }
            catch { }

            // Clean up sid cookie regardless
            if (Request.Cookies.ContainsKey(SessionCookie.Name))
            {
                Response.Cookies.Delete(SessionCookie.Name, new CookieOptions { Secure = true, SameSite = SameSiteMode.None });
            }

            await SignOutAllAsync();

            // РџСЂРёРѕСЂРёС‚РµС‚ вЂ” РµСЃР»Рё РµСЃС‚СЊ OIDC post_logout_redirect_uri
            var request = HttpContext.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
            {
                return SignOut(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = request.PostLogoutRedirectUri
                    });
            }

            var target = SafeReturn(ReturnUrl);
            return AutomaticRedirectAfterSignOut
                ? LocalRedirect(target)
                : Page();
        }

        private async Task SignOutAllAsync()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }

        private string SafeReturn(string? url)
            => (!string.IsNullOrWhiteSpace(url) && Url.IsLocalUrl(url)) ? url! : "/";
    }
}

