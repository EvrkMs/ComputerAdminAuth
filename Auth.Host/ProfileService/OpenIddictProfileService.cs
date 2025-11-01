// Auth.Host/ProfileService/OpenIddictProfileService.cs
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Host.ProfileService;

public interface IOpenIddictProfileService
{
    Task<ClaimsPrincipal> CreateAsync(UserEntity user, OpenIddictRequest request, CancellationToken ct = default);
}

public sealed class OpenIddictProfileService(
    SignInManager<UserEntity> signInManager,
    IOpenIddictScopeManager scopeManager,
    UserManager<UserEntity> userManager,
    RoleManager<IdentityRole<Guid>> roleManager) : IOpenIddictProfileService
{
    private readonly SignInManager<UserEntity> _signInManager = signInManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;
    private readonly UserManager<UserEntity> _userManager = userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager = roleManager;

    public async Task<ClaimsPrincipal> CreateAsync(UserEntity user, OpenIddictRequest request, CancellationToken ct = default)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;


        // ����������� sub/name
        identity.AddOrReplaceClaim(Claims.Subject, user.Id.ToString());
        if (!identity.HasClaim(c => c.Type == Claims.Name))
            identity.AddClaim(new Claim(Claims.Name, user.UserName ?? user.Id.ToString()));

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var roleName in roles)
        {
            identity.TryAddRole(roleName);
            // (�����������) claims ����� ����:
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role != null)
            {
                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var rc in roleClaims)
                    if (!identity.HasClaim(rc.Type, rc.Value))
                        identity.AddClaim(rc);
            }
            // Also add aggregate "roles" claim per role for SPA compatibility
            if (!identity.HasClaim("roles", roleName))
                identity.AddClaim(new Claim("roles", roleName));
        }
        // Scopes/resources
        principal.SetScopes(request.GetScopes());

        var resources = new List<string>();
        await foreach (var r in _scopeManager.ListResourcesAsync(principal.GetScopes(), ct))
            resources.Add(r);
        principal.SetResources(resources);

        // Destinations � ���� ����� ������
        ApplyDestinations(principal);
        return principal;
    }

    private static void ApplyDestinations(ClaimsPrincipal principal)
    {
        foreach (var claim in principal.Claims)
        {
            var dest = new List<string> { Destinations.AccessToken };

            switch (claim.Type)
            {
                case Claims.Subject:
                    dest.Add(Destinations.IdentityToken);
                    break;
                case "sid": // "sid" per OIDC Back-Channel Logout
                    dest.Add(Destinations.IdentityToken);
                    dest.Add(Destinations.AccessToken);
                    break;

                case Claims.Name:
                case Claims.PreferredUsername:
                case "full_name":
                    if (principal.HasScope(Scopes.Profile))
                        dest.Add(Destinations.IdentityToken);
                    break;

                case Claims.Email:
                    if (principal.HasScope(Scopes.Email))
                        dest.Add(Destinations.IdentityToken);
                    break;

                case Claims.PhoneNumber:
                    if (principal.HasScope(Scopes.Phone))
                        dest.Add(Destinations.IdentityToken);
                    break;

                case Claims.Role:          // "role"
                case ClaimTypes.Role:      // http://schemas.microsoft.com/ws/2008/06/identity/claims/role
                    // Always include roles in the id_token so SPAs can determine privileges
                    dest.Add(Destinations.IdentityToken);
                    break;

                case "AspNet.Identity.SecurityStamp":
                    dest.Clear(); // ������� �� �����
                    break;
            }

            if (dest.Count > 0)
                claim.SetDestinations(dest);
        }
    }
}

internal static class ClaimsIdentityExtensions
{
    public static void AddOrReplaceClaim(this ClaimsIdentity identity, string type, string value)
    {
        var existing = identity.FindFirst(type);
        if (existing is not null) identity.RemoveClaim(existing);
        identity.AddClaim(new Claim(type, value));
    }
}
internal static class ClaimsIdentityRoleExtensions
{
    public static void TryAddRole(this ClaimsIdentity identity, string roleValue)
    {
        // ��� ���� "role" ��� ClaimTypes.Role � ��� �� ���������?
        bool hasJwtRole = identity.HasClaim(c => c.Type == OpenIddictConstants.Claims.Role && c.Value == roleValue);
        bool hasWsRole = identity.HasClaim(c => c.Type == ClaimTypes.Role && c.Value == roleValue);

        if (!hasJwtRole)
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Role, roleValue));

        if (!hasWsRole)
            identity.AddClaim(new Claim(ClaimTypes.Role, roleValue));
    }
}



