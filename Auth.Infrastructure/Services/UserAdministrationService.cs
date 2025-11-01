using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Auth.Application;
using Auth.Application.UseCases.Users;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Services;

public sealed class UserAdministrationService : IUserAdministrationService
{
    private readonly AppDbContext _db;
    private readonly UserManager<UserEntity> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;

    public UserAdministrationService(
        AppDbContext db,
        UserManager<UserEntity> userManager,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        _db = db;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<IReadOnlyList<UserListItemDto>> ListAsync(string? query, UserStatus? status, CancellationToken ct = default)
    {
        IQueryable<UserEntity> q = _db.Users.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(query))
        {
            var qNorm = query.Trim();
            q = q.Where(u =>
                (u.Email != null && EF.Functions.ILike(u.Email, $"%{qNorm}%")) ||
                (u.UserName != null && EF.Functions.ILike(u.UserName, $"%{qNorm}%")) ||
                (u.FullName != null && EF.Functions.ILike(u.FullName, $"%{qNorm}%")) ||
                (u.PhoneNumber != null && EF.Functions.ILike(u.PhoneNumber, $"%{qNorm}%")));
        }

        if (status.HasValue)
        {
            q = q.Where(u => u.Status == status.Value);
        }

        var users = await q.OrderByDescending(u => u.CreatedAt).ToListAsync(ct);
        if (users.Count == 0)
            return Array.Empty<UserListItemDto>();

        var userIds = users.Select(u => u.Id).ToArray();
        var userRolePairs = await _db.UserRoles
            .Where(ur => userIds.Contains(ur.UserId))
            .Join(_db.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => new { ur.UserId, r.Name })
            .ToListAsync(ct);

        var rolesByUser = userRolePairs
            .GroupBy(x => x.UserId)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Name!).OrderBy(n => n).ToArray());

        return users
            .Select(u => ToDto(u, rolesByUser.GetValueOrDefault(u.Id, Array.Empty<string>())))
            .ToList();
    }

    public async Task<UserListItemDto?> GetAsync(Guid id, CancellationToken ct = default)
    {
        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
            return null;

        var roles = await _db.UserRoles
            .Where(ur => ur.UserId == id)
            .Join(_db.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name!)
            .OrderBy(n => n)
            .ToArrayAsync(ct);

        return ToDto(user, roles);
    }

    public async Task<IReadOnlyList<RoleDto>> ListRolesAsync(CancellationToken ct = default)
    {
        var roles = await _roleManager.Roles
            .AsNoTracking()
            .OrderBy(r => r.Name)
            .Select(r => new RoleDto(r.Id, r.Name ?? string.Empty))
            .ToListAsync(ct);

        return roles;
    }

    public async Task<OperationResult<UserListItemDto>> CreateAsync(CreateUserInput input, CancellationToken ct = default)
    {
        var rolesToAssign = await ResolveRolesAsync(input.Roles, ct);
        if (!rolesToAssign.Success)
            return OperationResult<UserListItemDto>.Validation(CloneErrors(rolesToAssign.ValidationErrors!));

        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            UserName = input.UserName,
            FullName = input.FullName,
            Status = input.Status,
            MustChangePassword = true,
            UpdatedAt = DateTime.UtcNow
        };

        var createRes = await _userManager.CreateAsync(user, input.Password);
        if (!createRes.Succeeded)
            return OperationResult<UserListItemDto>.Validation(ToValidationDictionary(createRes.Errors));

        if (rolesToAssign.Value is { Length: > 0 })
        {
            var addRolesRes = await _userManager.AddToRolesAsync(user, rolesToAssign.Value!);
            if (!addRolesRes.Succeeded)
                return OperationResult<UserListItemDto>.Validation(ToValidationDictionary(addRolesRes.Errors));
        }

        var dto = ToDto(user, rolesToAssign.Value ?? Array.Empty<string>());
        return OperationResult<UserListItemDto>.Ok(dto);
    }

    public async Task<OperationResult<UserListItemDto>> UpdateAsync(Guid id, UpdateUserInput input, CancellationToken ct = default)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
            return OperationResult<UserListItemDto>.Fail("not_found");

        var now = DateTime.UtcNow;
        var userUpdated = false;

        if (!string.IsNullOrWhiteSpace(input.FullName))
        {
            var trimmed = input.FullName.Trim();
            if (!string.Equals(user.FullName, trimmed, StringComparison.Ordinal))
            {
                user.FullName = trimmed;
                userUpdated = true;
            }
        }

        if (input.Status.HasValue && user.Status != input.Status.Value)
        {
            user.Status = input.Status.Value;
            userUpdated = true;
        }

        if (input.PhoneNumber is not null)
        {
            var normalizedPhone = string.IsNullOrWhiteSpace(input.PhoneNumber) ? null : input.PhoneNumber.Trim();
            if (!string.Equals(user.PhoneNumber, normalizedPhone, StringComparison.Ordinal))
            {
                user.PhoneNumber = normalizedPhone;
                userUpdated = true;
            }
        }

        string[] resultingRoles;
        var rolesChanged = false;

        if (input.Roles is not null)
        {
            var desiredResult = await ResolveRolesAsync(input.Roles, ct);
            if (!desiredResult.Success)
                return OperationResult<UserListItemDto>.Validation(CloneErrors(desiredResult.ValidationErrors!));

            var desiredRoles = desiredResult.Value ?? Array.Empty<string>();
            var currentRoles = await _userManager.GetRolesAsync(user);
            var toAdd = desiredRoles.Except(currentRoles, StringComparer.OrdinalIgnoreCase).ToArray();
            var toRemove = currentRoles.Except(desiredRoles, StringComparer.OrdinalIgnoreCase).ToArray();

            if (toAdd.Length > 0)
            {
                var addResult = await _userManager.AddToRolesAsync(user, toAdd);
                if (!addResult.Succeeded)
                    return OperationResult<UserListItemDto>.Validation(ToValidationDictionary(addResult.Errors));
                rolesChanged = true;
            }

            if (toRemove.Length > 0)
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, toRemove);
                if (!removeResult.Succeeded)
                    return OperationResult<UserListItemDto>.Validation(ToValidationDictionary(removeResult.Errors));
                rolesChanged = true;
            }

            resultingRoles = desiredRoles;
        }
        else
        {
            var currentRoles = await _userManager.GetRolesAsync(user);
            resultingRoles = currentRoles.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        if (userUpdated || rolesChanged)
        {
            user.UpdatedAt = now;
            var updateRes = await _userManager.UpdateAsync(user);
            if (!updateRes.Succeeded)
                return OperationResult<UserListItemDto>.Validation(ToValidationDictionary(updateRes.Errors));
        }

        if (!rolesChanged && input.Roles is null)
        {
            resultingRoles = resultingRoles.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        return OperationResult<UserListItemDto>.Ok(ToDto(user, resultingRoles));
    }

    public async Task<OperationResult> ChangePasswordAsync(Guid id, ChangePasswordInput input, CancellationToken ct = default)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
            return OperationResult.Fail("not_found");

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, resetToken, input.NewPassword);
        if (!result.Succeeded)
            return OperationResult.Validation(ToValidationDictionary(result.Errors));

        user.MustChangePassword = input.RequireChangeOnNextLogin;
        user.UpdatedAt = DateTime.UtcNow;

        await _userManager.UpdateSecurityStampAsync(user);

        var saveRes = await _userManager.UpdateAsync(user);
        if (!saveRes.Succeeded)
            return OperationResult.Validation(ToValidationDictionary(saveRes.Errors));

        return OperationResult.Ok();
    }

    public async Task<OperationResult<RoleDto>> CreateRoleAsync(CreateRoleInput input, CancellationToken ct = default)
    {
        var validationErrors = ValidateRoleName(input.Name);
        if (validationErrors is not null)
            return OperationResult<RoleDto>.Validation(validationErrors);

        var name = input.Name.Trim();
        if (await _roleManager.RoleExistsAsync(name))
        {
            return OperationResult<RoleDto>.Validation(new Dictionary<string, string[]>
            {
                ["Name"] = new[] {$"Роль '{name}' уже существует."}
            });
        }

        var role = new IdentityRole<Guid>(name);
        var createResult = await _roleManager.CreateAsync(role);
        if (!createResult.Succeeded)
            return OperationResult<RoleDto>.Validation(ToValidationDictionary(createResult.Errors));

        return OperationResult<RoleDto>.Ok(new RoleDto(role.Id, role.Name ?? name));
    }

    private async Task<OperationResult<string[]>> ResolveRolesAsync(IReadOnlyCollection<string>? requestedRoles, CancellationToken ct)
    {
        if (requestedRoles is null || requestedRoles.Count == 0)
            return OperationResult<string[]>.Ok(Array.Empty<string>());

        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var role in requestedRoles)
        {
            if (string.IsNullOrWhiteSpace(role)) continue;
            var trimmed = role.Trim();
            var normalizedKey = _roleManager.NormalizeKey(trimmed) ?? trimmed.ToUpperInvariant();
            if (!normalized.ContainsKey(normalizedKey))
            {
                normalized.Add(normalizedKey, trimmed);
            }
        }

        if (normalized.Count == 0)
            return OperationResult<string[]>.Ok(Array.Empty<string>());

        var normalizedKeys = normalized.Keys.ToArray();
        var existing = await _roleManager.Roles
            .AsNoTracking()
            .Where(r => normalizedKeys.Contains(r.NormalizedName!))
            .Select(r => new { r.Name, r.NormalizedName })
            .ToListAsync(ct);

        var resolved = existing
            .Where(r => !string.IsNullOrWhiteSpace(r.Name))
            .Select(r => r.Name!)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var missing = normalized
            .Where(pair => existing.All(r => !string.Equals(r.NormalizedName, pair.Key, StringComparison.OrdinalIgnoreCase)))
            .Select(pair => pair.Value)
            .ToArray();

        if (missing.Length > 0)
        {
            return OperationResult<string[]>.Validation(new Dictionary<string, string[]>
            {
                ["Roles"] = new[] {$"Не найдены роли: {string.Join(", ", missing)}"}
            });
        }

        return OperationResult<string[]>.Ok(resolved);
    }

    private static UserListItemDto ToDto(UserEntity u, IReadOnlyCollection<string> roles) => new()
    {
        Id = u.Id,
        UserName = u.UserName ?? string.Empty,
        Email = u.Email ?? string.Empty,
        FullName = u.FullName,
        PhoneNumber = u.PhoneNumber,
        Status = u.Status,
        IsActive = u.IsActive,
        MustChangePassword = u.MustChangePassword,
        CreatedAt = u.CreatedAt,
        UpdatedAt = u.UpdatedAt,
        Roles = roles.ToArray()
    };

    private static Dictionary<string, string[]> ToValidationDictionary(IEnumerable<IdentityError> errors)
    {
        var dict = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var err in errors)
        {
            var key = string.IsNullOrEmpty(err.Code) ? string.Empty : err.Code;
            if (!dict.TryGetValue(key, out var list))
            {
                list = new List<string>();
                dict[key] = list;
            }
            list.Add(err.Description);
        }

        return dict.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray());
    }

    private static Dictionary<string, string[]> CloneErrors(IReadOnlyDictionary<string, string[]> source)
        => source.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray(), StringComparer.OrdinalIgnoreCase);

    private static Dictionary<string, string[]>? ValidateRoleName(string? name)
    {
        var errors = new List<string>();
        var trimmed = name?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(trimmed))
            errors.Add("Название роли не может быть пустым.");
        else
        {
            if (trimmed.Length < 2)
                errors.Add("Название роли должно содержать минимум 2 символа.");
            if (trimmed.Length > 64)
                errors.Add("Название роли должно содержать не более 64 символов.");
        }

        return errors.Count == 0 ? null : new Dictionary<string, string[]> { ["Name"] = errors.ToArray() };
    }
}
