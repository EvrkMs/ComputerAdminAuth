using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Claims;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Services;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Auth.Tests.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Auth.Tests;

public class SessionBindingServiceTests
{
    [Fact]
    public async Task AttachInteractiveSessionAsync_RememberMeFalse_UsesShortLifetime()
    {
        await AssertAttachBehaviorAsync(rememberMe: false, expectedLifetime: TimeSpan.FromDays(1));
    }

    [Fact]
    public async Task AttachInteractiveSessionAsync_RememberMeTrue_UsesLongLifetime()
    {
        await AssertAttachBehaviorAsync(rememberMe: true, expectedLifetime: TimeSpan.FromDays(7));
    }

    private static async Task AssertAttachBehaviorAsync(bool rememberMe, TimeSpan expectedLifetime)
    {
        var (httpContext, authService) = CreateHttpContextWithAuthResult(rememberMe);

        var issuedSid = "sid" + Guid.NewGuid().ToString("N");
        var issuedSecret = "secret";
        var issuedExpires = DateTime.UtcNow.Add(expectedLifetime);

        TimeSpan? capturedLifetime = null;
        var sessionService = new Mock<ISessionService>();
        sessionService
            .Setup(s => s.EnsureInteractiveSessionAsync(
                It.IsAny<Guid>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<CancellationToken>()))
            .Callback<Guid, string?, string?, string?, string?, TimeSpan?, CancellationToken>((_, _, _, _, _, lifetime, _) =>
            {
                capturedLifetime = lifetime;
            })
            .ReturnsAsync(new SessionIssueResult(issuedSid, issuedSecret, DateTime.UtcNow, issuedExpires));

        var signInManager = IdentityTestHelper.CreateSignInManager();
        var guard = new SessionCookieGuard(sessionService.Object, signInManager, NullLogger<SessionCookieGuard>.Instance);
        var binder = new SessionCookieBinder(sessionService.Object);
        var service = new SessionBindingService(guard, binder);

        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var user = new UserEntity { Id = Guid.NewGuid() };

        await service.AttachInteractiveSessionAsync(httpContext, principal, user, clientId: "web");

        Assert.Equal(expectedLifetime, capturedLifetime);

        Assert.Contains(principal.Claims, c => c.Type == "sid" && c.Value == issuedSid);
        Assert.Contains(principal.Claims, c => c.Type == SessionClaimTypes.Persistence && c.Value == rememberMe.ToString().ToLowerInvariant());

        var cookieHeader = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(h => h.StartsWith($"{SessionCookie.Name}=", StringComparison.OrdinalIgnoreCase));
        var cookieHeaderValue = cookieHeader ?? string.Empty;
        Assert.False(string.IsNullOrEmpty(cookieHeaderValue));
        Assert.Contains(SessionCookie.Pack(issuedSid, issuedSecret), cookieHeaderValue);
        AssertCookieLifetime(cookieHeaderValue, expectedLifetime);

        Assert.NotNull(authService.LastTicket);
        Assert.Equal(issuedSid, authService.LastTicket!.Principal.FindFirst("sid")?.Value);
        Assert.Equal(rememberMe.ToString().ToLowerInvariant(), authService.LastTicket.Principal.FindFirst(SessionClaimTypes.Persistence)?.Value);
    }

    private static (DefaultHttpContext httpContext, TestAuthenticationService authService) CreateHttpContextWithAuthResult(bool rememberMe)
    {
        var identity = new ClaimsIdentity(authenticationType: IdentityConstants.ApplicationScheme);
        var principal = new ClaimsPrincipal(identity);
        var props = new AuthenticationProperties
        {
            IsPersistent = true
        };
        props.Items[CustomSignInManager.RememberMePropertyKey] = rememberMe ? "true" : "false";
        var ticket = new AuthenticationTicket(principal, props, IdentityConstants.ApplicationScheme);
        var result = AuthenticateResult.Success(ticket);
        var authService = new TestAuthenticationService(result);

        var services = new ServiceCollection()
            .AddSingleton<IAuthenticationService>(authService)
            .BuildServiceProvider();

        var context = new DefaultHttpContext
        {
            RequestServices = services
        };
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.1");
        context.Request.Headers["User-Agent"] = "unit-test";

        return (context, authService);
    }

    private static void AssertCookieLifetime(string setCookieHeader, TimeSpan expectedLifetime)
    {
        var expiresPart = setCookieHeader
            .Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(part => part.StartsWith("expires=", StringComparison.OrdinalIgnoreCase));

        Assert.False(string.IsNullOrEmpty(expiresPart));
        var expiresValue = expiresPart!.Substring("expires=".Length);
        var expiresAt = DateTimeOffset.Parse(expiresValue, CultureInfo.InvariantCulture);
        var delta = expiresAt - DateTimeOffset.UtcNow;
        Assert.InRange(delta.TotalHours, expectedLifetime.TotalHours - 1, expectedLifetime.TotalHours + 1);
    }

    private sealed class TestAuthenticationService : IAuthenticationService
    {
        private readonly AuthenticateResult _result;

        public TestAuthenticationService(AuthenticateResult result)
        {
            _result = result;
        }

        public AuthenticationTicket? LastTicket { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
            => Task.FromResult(_result);

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            LastTicket = new AuthenticationTicket(principal, properties ?? new AuthenticationProperties(), scheme ?? IdentityConstants.ApplicationScheme);
            return Task.CompletedTask;
        }

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;
    }
}
