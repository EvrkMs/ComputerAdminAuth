using Auth.Application.Interfaces;
using Auth.Infrastructure.OpenIddict;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Security.Claims;

namespace Auth.Tests;

public class EnsureSessionActiveForIntrospectionTests
{
    [Fact]
    public async Task HandleAsync_AllowsToken_WhenSessionActive()
    {
        var sessions = new Mock<ISessionService>();
        sessions.Setup(s => s.IsActiveAsync("sid-1", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var logger = Mock.Of<ILogger<EnsureSessionActiveForIntrospection>>();
        var handler = new EnsureSessionActiveForIntrospection(sessions.Object, logger);
        var context = CreateContext(sid: "sid-1", subject: "user-1");

        await handler.HandleAsync(context);

        Assert.False(context.IsRejected);
        sessions.Verify(s => s.IsActiveAsync("sid-1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_Rejects_WhenSidMissing()
    {
        var handler = new EnsureSessionActiveForIntrospection(
            Mock.Of<ISessionService>(),
            Mock.Of<ILogger<EnsureSessionActiveForIntrospection>>());

        var context = CreateContext(sid: null, subject: "user-2");

        await handler.HandleAsync(context);

        Assert.True(context.IsRejected);
        Assert.Equal(OpenIddictConstants.Errors.InvalidToken, context.Error);
    }

    [Fact]
    public async Task HandleAsync_Rejects_WhenSessionInactive()
    {
        var sessions = new Mock<ISessionService>();
        sessions.Setup(s => s.IsActiveAsync("sid-3", It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var handler = new EnsureSessionActiveForIntrospection(
            sessions.Object,
            Mock.Of<ILogger<EnsureSessionActiveForIntrospection>>());

        var context = CreateContext(sid: "sid-3", subject: "user-3");

        await handler.HandleAsync(context);

        Assert.True(context.IsRejected);
        Assert.Equal(OpenIddictConstants.Errors.InvalidToken, context.Error);
    }

    private static OpenIddictServerEvents.HandleIntrospectionRequestContext CreateContext(string? sid, string? subject)
    {
        var transaction = new OpenIddictServerTransaction();
        transaction.Logger = Mock.Of<ILogger>();
        transaction.Options = new OpenIddictServerOptions();

        var context = new OpenIddictServerEvents.HandleIntrospectionRequestContext(transaction);

        var identity = new ClaimsIdentity();
        if (!string.IsNullOrEmpty(subject))
        {
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, subject));
        }

        if (!string.IsNullOrEmpty(sid))
        {
            identity.AddClaim(new Claim("sid", sid));
        }

        context.GenericTokenPrincipal = new ClaimsPrincipal(identity);

        return context;
    }
}
