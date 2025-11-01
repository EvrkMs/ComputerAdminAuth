using System.IO;
using System.Security.Claims;
using Auth.Application.Interfaces;
using Auth.Host.Middleware;
using Microsoft.AspNetCore.Http;
using Moq;
using OpenIddict.Abstractions;

namespace Auth.Tests;

public class SessionRevocationMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_BlocksRequestsWithoutSid()
    {
        var context = CreateContext(withSid: false);
        var sessions = new Mock<ISessionService>();
        var middleware = new SessionRevocationMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context, sessions.Object);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        AssertResponsePayload(context, "session_required");
    }

    [Fact]
    public async Task InvokeAsync_BlocksRevokedSession()
    {
        var context = CreateContext(withSid: true);
        var sessions = new Mock<ISessionService>();
        sessions.Setup(s => s.IsActiveAsync("live-sid", It.IsAny<CancellationToken>())).ReturnsAsync(false);
        var middleware = new SessionRevocationMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context, sessions.Object);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        AssertResponsePayload(context, "session_revoked");
    }

    [Fact]
    public async Task InvokeAsync_AllowsActiveSession()
    {
        var context = CreateContext(withSid: true);
        var sessions = new Mock<ISessionService>();
        sessions.Setup(s => s.IsActiveAsync("live-sid", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var invoked = false;
        var middleware = new SessionRevocationMiddleware(_ =>
        {
            invoked = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, sessions.Object);

        Assert.True(invoked);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    private static DefaultHttpContext CreateContext(bool withSid)
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Path = "/api/data";
        context.Request.Headers["Authorization"] = "Bearer token";

        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, "user")
        };
        if (withSid)
            claims.Add(new Claim("sid", "live-sid"));

        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
        return context;
    }

    private static void AssertResponsePayload(DefaultHttpContext context, string expectedError)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        var body = reader.ReadToEnd();
        Assert.Contains($"\"{expectedError}\"", body);
    }
}
