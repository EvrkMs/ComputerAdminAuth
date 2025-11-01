using System.Security.Claims;
using Auth.Domain.Entities;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Auth.Tests.Helpers;

internal static class IdentityTestHelper
{
    public static Mock<UserManager<UserEntity>> CreateUserManagerMock()
    {
        var store = new Mock<IUserStore<UserEntity>>();
        var options = Options.Create(new IdentityOptions());
        var passwordHasher = new PasswordHasher<UserEntity>();
        var userValidators = Array.Empty<IUserValidator<UserEntity>>();
        var passwordValidators = Array.Empty<IPasswordValidator<UserEntity>>();
        var keyNormalizer = new UpperInvariantLookupNormalizer();
        var errors = new IdentityErrorDescriber();
        var services = new Mock<IServiceProvider>();
        var logger = new Mock<ILogger<UserManager<UserEntity>>>();

        var manager = new Mock<UserManager<UserEntity>>(
            store.Object,
            options,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services.Object,
            logger.Object);

        return manager;
    }

    public static TestCustomSignInManager CreateSignInManager(
        Mock<UserManager<UserEntity>>? userManager = null,
        IHttpContextAccessor? accessor = null)
    {
        var principalFactory = new Mock<IUserClaimsPrincipalFactory<UserEntity>>();
        principalFactory
            .Setup(f => f.CreateAsync(It.IsAny<UserEntity>()))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        var logger = new Mock<ILogger<SignInManager<UserEntity>>>();
        var schemes = new Mock<IAuthenticationSchemeProvider>();
        var confirmation = new Mock<IUserConfirmation<UserEntity>>();

        accessor ??= new HttpContextAccessor { HttpContext = new DefaultHttpContext() };

        return new TestCustomSignInManager(
            userManager?.Object ?? CreateUserManagerMock().Object,
            accessor,
            principalFactory.Object,
            Options.Create(new IdentityOptions()),
            logger.Object,
            schemes.Object,
            confirmation.Object);
    }
}

internal sealed class TestCustomSignInManager : CustomSignInManager
{
    public AuthenticationProperties? CapturedAuthenticationProperties { get; private set; }
    public UserEntity? CapturedUser { get; private set; }
    public bool? CapturedRememberMe { get; private set; }

    public TestCustomSignInManager(
        UserManager<UserEntity> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<UserEntity> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<UserEntity>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<UserEntity> confirmation)
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
    }

    public override Task SignInAsync(UserEntity user, AuthenticationProperties authenticationProperties, string? authenticationMethod = null)
    {
        CapturedUser = user;
        CapturedAuthenticationProperties = authenticationProperties;
        return Task.CompletedTask;
    }

    public override Task SignInWithSessionPolicyAsync(UserEntity user, bool rememberMe)
    {
        CapturedRememberMe = rememberMe;
        return base.SignInWithSessionPolicyAsync(user, rememberMe);
    }

    public void Reset()
    {
        CapturedAuthenticationProperties = null;
        CapturedUser = null;
        CapturedRememberMe = null;
    }
}
