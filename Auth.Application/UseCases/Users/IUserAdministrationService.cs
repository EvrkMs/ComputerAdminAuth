using Auth.Domain.Entities;

namespace Auth.Application.UseCases.Users;

public interface IUserAdministrationService
{
    Task<IReadOnlyList<UserListItemDto>> ListAsync(string? query, UserStatus? status, CancellationToken ct = default);
    Task<UserListItemDto?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<RoleDto>> ListRolesAsync(CancellationToken ct = default);
    Task<OperationResult<UserListItemDto>> CreateAsync(CreateUserInput input, CancellationToken ct = default);
    Task<OperationResult<UserListItemDto>> UpdateAsync(Guid id, UpdateUserInput input, CancellationToken ct = default);
    Task<OperationResult> ChangePasswordAsync(Guid id, ChangePasswordInput input, CancellationToken ct = default);
    Task<OperationResult<RoleDto>> CreateRoleAsync(CreateRoleInput input, CancellationToken ct = default);
}
