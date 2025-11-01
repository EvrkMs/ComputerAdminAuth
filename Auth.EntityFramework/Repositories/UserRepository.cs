using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Repositories;

public class UserRepository : IUserRepository
{
    private readonly AppDbContext _db;

    public UserRepository(AppDbContext db) => _db = db;

    public Task<UserEntity?> GetByIdAsync(Guid userId, CancellationToken ct = default) =>
        _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct);
}
