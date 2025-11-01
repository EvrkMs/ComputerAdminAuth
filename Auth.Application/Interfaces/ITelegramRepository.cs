using Auth.Domain.Entities;

namespace Auth.Application.Interfaces;

public interface ITelegramRepository
{
    Task<TelegramEntity?> GetByTelegramIdAsync(long telegramId, CancellationToken ct = default);
    Task<TelegramEntity?> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<TelegramEntity?> GetByUserIdForUpdateAsync(Guid userId, CancellationToken ct = default);
    Task AddAsync(TelegramEntity entity, CancellationToken ct = default);
    Task UpdateAsync(TelegramEntity entity, CancellationToken ct = default);
    Task RemoveAsync(TelegramEntity entity, CancellationToken ct = default);
}
