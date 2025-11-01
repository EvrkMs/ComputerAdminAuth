using Auth.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure;

public class CustomSignInManager : SignInManager<UserEntity>
{
    public const string RememberMePropertyKey = "auth.remember_me";
    public static readonly TimeSpan ShortSessionLifetime = TimeSpan.FromDays(1);
    public static readonly TimeSpan LongSessionLifetime = TimeSpan.FromDays(7);

    public CustomSignInManager(UserManager<UserEntity> userManager,
        IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<UserEntity> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<UserEntity>> logger,
        IAuthenticationSchemeProvider schemes, IUserConfirmation<UserEntity> confirmation)
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation) { }

    public override async Task<SignInResult> PasswordSignInAsync(
        string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var user = await UserManager.FindByNameAsync(userName);
        if (user is not null && user.MustChangePassword)
        {
            return SignInResult.NotAllowed; // вместо успешного логина
        }

        var result = await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);

        if (result.Succeeded && user is not null)
        {
            await SignInWithSessionPolicyAsync(user, rememberMe: isPersistent);
        }

        return result;
    }

    public virtual Task SignInWithSessionPolicyAsync(UserEntity user, bool rememberMe)
    {
        ArgumentNullException.ThrowIfNull(user);
        var props = BuildAuthenticationProperties(rememberMe);
        return SignInAsync(user, props);
    }

    private static AuthenticationProperties BuildAuthenticationProperties(bool rememberMe)
    {
        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            AllowRefresh = rememberMe,
            IssuedUtc = DateTimeOffset.UtcNow,
            ExpiresUtc = DateTimeOffset.UtcNow + (rememberMe ? LongSessionLifetime : ShortSessionLifetime)
        };
        props.Items[RememberMePropertyKey] = rememberMe ? "true" : "false";
        return props;
    }
}
