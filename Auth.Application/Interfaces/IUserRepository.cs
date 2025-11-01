using Auth.Domain.Entities;

namespace Auth.Application.Interfaces;

public interface IUserRepository
{
    Task<UserEntity?> GetByIdAsync(Guid userId, CancellationToken ct = default);
}

