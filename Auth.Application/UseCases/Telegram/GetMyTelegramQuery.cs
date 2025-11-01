namespace Auth.Application.UseCases.Telegram;

using Auth.Application.Interfaces;
using Auth.Domain.Entities;

public class GetMyTelegramQuery
{
    private readonly ITelegramRepository _telegramRepo;

    public GetMyTelegramQuery(ITelegramRepository telegramRepo)
    {
        _telegramRepo = telegramRepo;
    }

    public async Task<TelegramEntity?> ExecuteAsync(Guid currentUserId, CancellationToken ct = default)
    {
        return await _telegramRepo.GetByUserIdAsync(currentUserId, ct);
    }
}
