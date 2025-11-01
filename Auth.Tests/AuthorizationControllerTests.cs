using System.IO;
using System.Security.Claims;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.ProfileService;
using Auth.Host.Services;
using Auth.Host.Services.Authorization;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Auth.Tests.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;

namespace Auth.Tests;

public class AuthorizationControllerTests
{
    [Fact]
    public async Task TryRestoreIdentityFromSessionCookieAsync_RestoresIdentity_WhenSessionValid()
    {
        var user = new UserEntity { Id = Guid.NewGuid(), Status = UserStatus.Active };
        var userManager = IdentityTestHelper.CreateUserManagerMock();
        userManager.Setup(m => m.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);

        var sessionResult = new SessionValidationResult(Guid.NewGuid(), user.Id, DateTime.UtcNow, DateTime.UtcNow.AddDays(7), false);
        var sessionService = new Mock<ISessionService>();
        sessionService.Setup(s => s.ValidateBrowserSessionAsync("ref1", "secret", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(sessionResult);

        var httpContext = CreateHttpContextWithSidCookie("ref1", "secret");
        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });

        var service = CreateService(userManager.Object, signInManager, sessionService.Object);

        var restored = await service.TryRestoreIdentityFromSessionCookieAsync(httpContext);

        Assert.True(restored);
        Assert.Equal(user, signInManager.CapturedUser);
        Assert.True(signInManager.CapturedRememberMe);
        userManager.Verify(m => m.FindByIdAsync(user.Id.ToString()), Times.Once);
    }

    [Fact]
    public async Task TryRestoreIdentityFromSessionCookieAsync_RevokesSession_WhenUserMissing()
    {
        var userManager = IdentityTestHelper.CreateUserManagerMock();
        userManager.Setup(m => m.FindByIdAsync(It.IsAny<string>())).ReturnsAsync((UserEntity?)null);

        var sessionResult = new SessionValidationResult(Guid.NewGuid(), Guid.NewGuid(), DateTime.UtcNow, DateTime.UtcNow.AddDays(1), false);
        var sessionService = new Mock<ISessionService>();
        sessionService.Setup(s => s.ValidateBrowserSessionAsync("ref2", "secret", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(sessionResult);

        var httpContext = CreateHttpContextWithSidCookie("ref2", "secret");
        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });

        var service = CreateService(userManager.Object, signInManager, sessionService.Object);

        var restored = await service.TryRestoreIdentityFromSessionCookieAsync(httpContext);

        Assert.False(restored);
        sessionService.Verify(s => s.RevokeAsync("ref2", "user_missing_or_inactive", null, It.IsAny<CancellationToken>()), Times.Once);
        Assert.Null(signInManager.CapturedUser);
        AssertCookieCleared(httpContext);
    }

    [Fact]
    public async Task TryRestoreIdentityFromSessionCookieAsync_ReturnsFalse_WhenSessionInvalid()
    {
        var userManager = IdentityTestHelper.CreateUserManagerMock();
        var sessionService = new Mock<ISessionService>();
        sessionService.Setup(s => s.ValidateBrowserSessionAsync("ref3", "secret", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync((SessionValidationResult?)null);

        var httpContext = CreateHttpContextWithSidCookie("ref3", "secret");
        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });

        var service = CreateService(userManager.Object, signInManager, sessionService.Object);

        var restored = await service.TryRestoreIdentityFromSessionCookieAsync(httpContext);

        Assert.False(restored);
        AssertCookieCleared(httpContext);
    }

    private static AuthorizationInteractionService CreateService(
        UserManager<UserEntity> userManager,
        CustomSignInManager signInManager,
        ISessionService sessions)
    {
        var guard = new SessionCookieGuard(sessions, signInManager);
        var binder = new SessionCookieBinder(sessions);

        return new AuthorizationInteractionService(
            Mock.Of<IOpenIddictApplicationManager>(),
            Mock.Of<IOpenIddictAuthorizationManager>(),
            signInManager,
            userManager,
            Mock.Of<IOpenIddictProfileService>(),
            sessions,
            new SessionBindingService(guard, binder));
    }

    private static DefaultHttpContext CreateHttpContextWithSidCookie(string reference, string secret)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = CreateAuthenticationServices()
        };
        var cookieValue = SessionCookie.Pack(reference, secret);
        context.Request.Headers["Cookie"] = $"{SessionCookie.Name}={cookieValue}";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static IServiceProvider CreateAuthenticationServices()
    {
        return new ServiceCollection()
            .AddLogging()
            .AddSingleton<IAuthenticationService, NoopAuthenticationService>()
            .BuildServiceProvider();
    }

    private sealed class NoopAuthenticationService : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.NoResult());
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    private static void AssertCookieCleared(DefaultHttpContext context)
    {
        var header = context.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains($"{SessionCookie.Name}=", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("expires=Thu, 01 Jan 1970", header, StringComparison.OrdinalIgnoreCase);
    }
}
