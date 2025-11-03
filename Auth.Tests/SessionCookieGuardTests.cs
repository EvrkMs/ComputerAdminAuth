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
using OpenIddict.Abstractions;

namespace Auth.Tests;

public class SessionCookieGuardTests
{
    [Fact]
    public async Task EnsureCookieSessionOrChallengeAsync_RevokesOnMismatch()
    {
        var httpContext = CreateHttpContextWithSid("sid-claim", "sid-cookie", subject: Guid.NewGuid().ToString());
        var sessionService = new Mock<ISessionService>();
        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });

        var guard = new SessionCookieGuard(sessionService.Object, signInManager, NullLogger<SessionCookieGuard>.Instance);
        var request = new OpenIddictRequest();

        var result = await guard.EnsureCookieSessionOrChallengeAsync(httpContext, request);

        Assert.False(result.Ok);
        sessionService.Verify(s => s.RevokeAsync("sid-cookie", "cookie_mismatch", It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        sessionService.Verify(s => s.RevokeAsync("sid-claim", "cookie_mismatch", It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EnsureCookieSessionOrChallengeAsync_ReturnsOk_WhenValidationSucceeds()
    {
        var subject = Guid.NewGuid();
        var httpContext = CreateHttpContextWithSid("sid-valid", "sid-valid", subject.ToString());

        var validation = new SessionValidationResult(Guid.NewGuid(), subject, DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddHours(1), false);
        var sessionService = new Mock<ISessionService>();
        sessionService.Setup(s => s.ValidateBrowserSessionAsync("sid-valid", "secret", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(validation);

        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });
        var guard = new SessionCookieGuard(sessionService.Object, signInManager, NullLogger<SessionCookieGuard>.Instance);

        var result = await guard.EnsureCookieSessionOrChallengeAsync(httpContext, new OpenIddictRequest());

        Assert.True(result.Ok);
        Assert.Null(result.Action);
        Assert.Equal("sid-valid", httpContext.Items["sid"]);
        sessionService.Verify(s => s.RevokeAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EnsureCookieSessionOrChallengeAsync_RevokesOnInactiveSession()
    {
        var subject = Guid.NewGuid().ToString();
        var httpContext = CreateHttpContextWithSid("sid-inactive", "sid-inactive", subject);

        var sessionService = new Mock<ISessionService>();
        sessionService.Setup(s => s.ValidateBrowserSessionAsync("sid-inactive", "secret", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync((SessionValidationResult?)null);

        var signInManager = IdentityTestHelper.CreateSignInManager(accessor: new HttpContextAccessor { HttpContext = httpContext });
        var guard = new SessionCookieGuard(sessionService.Object, signInManager, NullLogger<SessionCookieGuard>.Instance);

        var result = await guard.EnsureCookieSessionOrChallengeAsync(httpContext, new OpenIddictRequest());

        Assert.False(result.Ok);
        sessionService.Verify(s => s.RevokeAsync("sid-inactive", "session_inactive", subject, It.IsAny<CancellationToken>()), Times.Once);
    }

    private static DefaultHttpContext CreateHttpContextWithSid(string claimSid, string cookieSid, string subject)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = BuildAuthServices(claimSid, subject)
        };

        httpContext.Response.Body = new MemoryStream();
        httpContext.Request.Headers["Cookie"] = $"{SessionCookie.Name}={SessionCookie.Pack(cookieSid, "secret")}";

        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.5");

        return httpContext;
    }

    private static IServiceProvider BuildAuthServices(string sid, string subject)
    {
        var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
        identity.AddClaim(new Claim("sid", sid));
        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, subject));
        var principal = new ClaimsPrincipal(identity);
        var props = new AuthenticationProperties();
        var ticket = new AuthenticationTicket(principal, props, IdentityConstants.ApplicationScheme);
        var result = AuthenticateResult.Success(ticket);

        var authService = new Mock<IAuthenticationService>();
        authService
            .Setup(a => a.AuthenticateAsync(It.IsAny<HttpContext>(), IdentityConstants.ApplicationScheme))
            .ReturnsAsync(result);

        return new ServiceCollection()
            .AddSingleton(authService.Object)
            .AddLogging()
            .BuildServiceProvider();
    }
}
