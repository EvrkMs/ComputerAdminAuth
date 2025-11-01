using Auth.Domain.Entities;
using Auth.Infrastructure;
using Auth.Tests.Helpers;

namespace Auth.Tests;

public class CustomSignInManagerTests
{
    [Fact]
    public async Task SignInWithSessionPolicyAsync_RememberMeFalse_UsesOneDayLifetime()
    {
        var manager = IdentityTestHelper.CreateSignInManager();
        var user = new UserEntity { Id = Guid.NewGuid() };

        await manager.SignInWithSessionPolicyAsync(user, rememberMe: false);

        Assert.Equal(user, manager.CapturedUser);
        Assert.NotNull(manager.CapturedAuthenticationProperties);
        var props = manager.CapturedAuthenticationProperties!;
        Assert.False(props.AllowRefresh);
        Assert.True(props.IsPersistent);
        Assert.Equal("false", props.Items[CustomSignInManager.RememberMePropertyKey]);
        AssertApproxHours(props.IssuedUtc, props.ExpiresUtc, 24);
    }

    [Fact]
    public async Task SignInWithSessionPolicyAsync_RememberMeTrue_UsesSevenDayLifetime()
    {
        var manager = IdentityTestHelper.CreateSignInManager();
        var user = new UserEntity { Id = Guid.NewGuid() };

        await manager.SignInWithSessionPolicyAsync(user, rememberMe: true);

        Assert.Equal(user, manager.CapturedUser);
        var props = manager.CapturedAuthenticationProperties!;
        Assert.True(props.AllowRefresh);
        Assert.True(props.IsPersistent);
        Assert.Equal("true", props.Items[CustomSignInManager.RememberMePropertyKey]);
        AssertApproxHours(props.IssuedUtc, props.ExpiresUtc, 24 * 7);
    }

    private static void AssertApproxHours(DateTimeOffset? issued, DateTimeOffset? expires, int expectedHours)
    {
        Assert.NotNull(issued);
        Assert.NotNull(expires);
        var delta = (expires!.Value - issued!.Value).TotalHours;
        Assert.InRange(delta, expectedHours - 0.25, expectedHours + 0.25);
    }
}
