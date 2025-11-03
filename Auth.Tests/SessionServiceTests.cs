using System;
using System.Collections.Generic;
using Auth.EntityFramework.Data;
using Auth.EntityFramework.Repositories;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Moq;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

public sealed class SessionServiceTests : IDisposable
{
    private readonly AppDbContext _db;
    private readonly SessionRepository _repository;
    private readonly SessionService _service;
    private readonly UnitOfWork _unitOfWork;
    private readonly Mock<IOpenIddictAuthorizationManager> _authorizationManager;
    private readonly Mock<IOpenIddictTokenManager> _tokenManager;
    private readonly List<string> _revokedAuthorizationIds = [];

    public SessionServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _db = new AppDbContext(options);
        _repository = new SessionRepository(_db);
        _unitOfWork = new UnitOfWork(_db);

        _authorizationManager = new Mock<IOpenIddictAuthorizationManager>(MockBehavior.Loose);
        _authorizationManager
            .Setup(m => m.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>((id, _) => new ValueTask<object?>(id));
        _authorizationManager
            .Setup(m => m.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<bool>(true))
            .Callback<object, CancellationToken>((auth, _) =>
            {
                if (auth is string id)
                    _revokedAuthorizationIds.Add(id);
            });

        _tokenManager = new Mock<IOpenIddictTokenManager>(MockBehavior.Loose);
        _tokenManager
            .Setup(m => m.FindByAuthorizationIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(EmptyTokens());
        _tokenManager
            .Setup(m => m.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<bool>(true));

        _service = new SessionService(
            _repository,
            _db,
            _unitOfWork,
            _authorizationManager.Object,
            _tokenManager.Object,
            NullLogger<SessionService>.Instance);
    }

    [Fact]
    public async Task IssueSession_ValidatesAndRotatesBrowserSecret()
    {
        var userId = Guid.NewGuid();

        var issued = await _service.EnsureInteractiveSessionAsync(
            userId,
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromHours(1));

        Assert.Equal(32, issued.ReferenceId.Length);
        Assert.False(string.IsNullOrWhiteSpace(issued.BrowserSecret));
        Assert.NotEqual(default, issued.CreatedAt);
        Assert.NotNull(issued.ExpiresAt);

        var stored = await _repository.GetByReferenceAsync(issued.ReferenceId);
        Assert.NotNull(stored);
        Assert.Equal(userId, stored!.UserId);
        Assert.NotEqual(issued.BrowserSecret, stored.SecretHash);

        var validation = await _service.ValidateBrowserSessionAsync(issued.ReferenceId, issued.BrowserSecret);
        Assert.True(validation.HasValue);
        Assert.Equal(userId, validation!.Value.UserId);

        var wrong = await _service.ValidateBrowserSessionAsync(issued.ReferenceId, "not-the-secret");
        Assert.Null(wrong);

        var rotated = await _service.RefreshBrowserSecretAsync(issued.ReferenceId, userId);
        Assert.NotNull(rotated);
        Assert.NotEqual(issued.BrowserSecret, rotated!.Value.BrowserSecret);
        Assert.Equal(issued.CreatedAt, rotated.Value.CreatedAt);
        Assert.Equal(issued.ExpiresAt, rotated.Value.ExpiresAt);

        Assert.Null(await _service.ValidateBrowserSessionAsync(issued.ReferenceId, issued.BrowserSecret));
        Assert.True((await _service.ValidateBrowserSessionAsync(issued.ReferenceId, rotated.Value.BrowserSecret)).HasValue);

        var authorizationId = "auth-id";
        var linked = await _service.LinkAuthorizationAsync(issued.ReferenceId, authorizationId);
        Assert.True(linked);
        var linkRow = await _db.UserSessionAuthorizations.SingleAsync();
        Assert.Equal(stored!.Id, linkRow.SessionId);
        Assert.Equal(authorizationId, linkRow.AuthorizationId);

        var revoked = await _service.RevokeAsync(issued.ReferenceId, reason: "unit-test", by: "tester");
        Assert.True(revoked);
        Assert.False(await _service.IsActiveAsync(issued.ReferenceId));
        Assert.Null(await _service.ValidateBrowserSessionAsync(issued.ReferenceId, rotated.Value.BrowserSecret));
    }

    [Fact]
    public async Task ValidateBrowserSessionAsync_RespectsRequireActiveFlag()
    {
        var issued = await _service.EnsureInteractiveSessionAsync(
            Guid.NewGuid(),
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromMinutes(10));

        var stored = await _repository.GetByReferenceAsync(issued.ReferenceId);
        Assert.NotNull(stored);
        stored!.ExpiresAt = DateTime.UtcNow.AddMinutes(-5);
        await _repository.UpdateAsync(stored);
        await _unitOfWork.SaveChangesAsync();

        var strict = await _service.ValidateBrowserSessionAsync(issued.ReferenceId, issued.BrowserSecret);
        Assert.Null(strict);

        var relaxed = await _service.ValidateBrowserSessionAsync(issued.ReferenceId, issued.BrowserSecret, requireActive: false);
        Assert.True(relaxed.HasValue);
        Assert.Equal(stored.Id, relaxed!.Value.SessionId);
    }

    [Fact]
    public async Task IsActiveAsync_ReturnsFalse_WhenSessionMissing()
    {
        var issued = await _service.EnsureInteractiveSessionAsync(
            Guid.NewGuid(),
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromMinutes(30));

        var stored = await _repository.GetByReferenceAsync(issued.ReferenceId);
        Assert.NotNull(stored);

        await _repository.DeleteAsync(stored!);
        await _unitOfWork.SaveChangesAsync();

        var active = await _service.IsActiveAsync(issued.ReferenceId);
        Assert.False(active);
    }

    [Fact]
    public async Task ValidateBrowserSessionAsync_ReturnsNull_WhenSessionMissing()
    {
        var issued = await _service.EnsureInteractiveSessionAsync(
            Guid.NewGuid(),
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromMinutes(30));

        var stored = await _repository.GetByReferenceAsync(issued.ReferenceId);
        Assert.NotNull(stored);

        await _repository.DeleteAsync(stored!);
        await _unitOfWork.SaveChangesAsync();

        var validation = await _service.ValidateBrowserSessionAsync(issued.ReferenceId, issued.BrowserSecret);
        Assert.Null(validation);
    }

    [Fact]
    public async Task GetActiveReferenceByAuthorizationIdAsync_ReturnsReference_WhenActive()
    {
        var issued = await _service.EnsureInteractiveSessionAsync(
            Guid.NewGuid(),
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromMinutes(30));

        var authorizationId = Guid.NewGuid().ToString();
        await _service.LinkAuthorizationAsync(issued.ReferenceId, authorizationId);

        var resolved = await _service.GetActiveReferenceByAuthorizationIdAsync(authorizationId);
        Assert.Equal(issued.ReferenceId, resolved);

        await _service.RevokeAsync(issued.ReferenceId);

        var afterRevoke = await _service.GetActiveReferenceByAuthorizationIdAsync(authorizationId);
        Assert.Null(afterRevoke);
    }

    [Fact]
    public async Task RevokeAsync_CascadesToAllLinkedAuthorizations()
    {
        var issued = await _service.EnsureInteractiveSessionAsync(
            Guid.NewGuid(),
            clientId: "test-client",
            ip: "127.0.0.1",
            userAgent: "testsuite",
            device: "unit-test",
            absoluteLifetime: TimeSpan.FromMinutes(30));

        var firstAuth = Guid.NewGuid().ToString();
        var secondAuth = Guid.NewGuid().ToString();

        await _service.LinkAuthorizationAsync(issued.ReferenceId, firstAuth);
        await _service.LinkAuthorizationAsync(issued.ReferenceId, secondAuth);

        var session = await _repository.GetByReferenceAsync(issued.ReferenceId);
        Assert.NotNull(session);
        Assert.Contains(session!.Authorizations, x => x.AuthorizationId == firstAuth);
        Assert.Contains(session.Authorizations, x => x.AuthorizationId == secondAuth);

        _revokedAuthorizationIds.Clear();
        var revoked = await _service.RevokeAsync(issued.ReferenceId, reason: "cascade-test");
        Assert.True(revoked);
        Assert.Contains(firstAuth, _revokedAuthorizationIds);
        Assert.Contains(secondAuth, _revokedAuthorizationIds);
    }

    private static IAsyncEnumerable<object> EmptyTokens()
    {
        return Inner();

        static async IAsyncEnumerable<object> Inner()
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    public void Dispose()
    {
        _db.Dispose();
    }
}
