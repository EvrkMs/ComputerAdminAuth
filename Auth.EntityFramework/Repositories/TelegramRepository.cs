using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Repositories;

public class TelegramRepository : ITelegramRepository
{
    private readonly AppDbContext _db;

    public TelegramRepository(AppDbContext db) => _db = db;

    public Task<TelegramEntity?> GetByUserIdAsync(Guid userId, CancellationToken ct = default) =>
        _db.TelegramEntities.AsNoTracking().SingleOrDefaultAsync(t => t.UserId == userId, ct);

    public Task<TelegramEntity?> GetByUserIdForUpdateAsync(Guid userId, CancellationToken ct = default) =>
        _db.TelegramEntities.SingleOrDefaultAsync(t => t.UserId == userId, cancellationToken: ct);

    public Task<TelegramEntity?> GetByTelegramIdAsync(long telegramId, CancellationToken ct = default) =>
        _db.TelegramEntities.AsNoTracking().SingleOrDefaultAsync(t => t.TelegramId == telegramId, cancellationToken: ct);

    public async Task AddAsync(TelegramEntity entity, CancellationToken ct = default) =>
        await _db.TelegramEntities.AddAsync(entity, ct);

    public Task RemoveAsync(TelegramEntity entity, CancellationToken ct = default)
    {
        _db.TelegramEntities.Remove(entity);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(TelegramEntity entity, CancellationToken ct = default)
    {
        _db.TelegramEntities.Update(entity);
        return Task.CompletedTask;
    }
}
