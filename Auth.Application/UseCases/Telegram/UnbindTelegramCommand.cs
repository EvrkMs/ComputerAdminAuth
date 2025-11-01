namespace Auth.Application.UseCases.Telegram;

using Auth.Application;
using Auth.Application.Interfaces;

public class UnbindTelegramCommand
{
    private readonly ITelegramRepository _telegramRepo;
    private readonly IUnitOfWork _unitOfWork;
    public UnbindTelegramCommand(ITelegramRepository telegramRepo, IUnitOfWork unitOfWork)
    {
        _telegramRepo = telegramRepo;
        _unitOfWork = unitOfWork;
    }

    public async Task<Result> ExecuteAsync(Guid currentUserId, CancellationToken ct = default)
    {
        var tg = await _telegramRepo.GetByUserIdForUpdateAsync(currentUserId, ct);
        if (tg == null)
            return Result.Fail("not bound");

        try
        {
            await _telegramRepo.RemoveAsync(tg, ct);
            await _unitOfWork.SaveChangesAsync(ct);
            return Result.Ok();
        }
        catch
        {
            return Result.Fail("Не удалось отвязать.");
        }
    }
}
