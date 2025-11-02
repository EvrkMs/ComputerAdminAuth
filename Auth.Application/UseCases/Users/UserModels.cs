using System;
using System.Collections.Generic;
using Auth.Domain.Entities;

namespace Auth.Application.UseCases.Users;

public sealed record RoleDto(Guid Id, string Name);

public sealed record UserListItemDto
{
    public Guid Id { get; init; }
    public string UserName { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public string? PhoneNumber { get; init; }
    public UserStatus Status { get; init; }
    public bool IsActive { get; init; }
    public bool MustChangePassword { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime? UpdatedAt { get; init; }
    public string[] Roles { get; init; } = Array.Empty<string>();
}

public sealed record CreateUserInput(
    string UserName,
    string Password,
    string FullName,
    UserStatus Status,
    IReadOnlyCollection<string> Roles);

public sealed record UpdateUserInput(
    string? FullName,
    string? PhoneNumber,
    UserStatus? Status,
    IReadOnlyCollection<string>? Roles);

public sealed record ChangePasswordInput(
    string NewPassword,
    bool RequireChangeOnNextLogin);

public sealed record CreateRoleInput(string Name);
public sealed record UpdateRoleInput(string Name);
