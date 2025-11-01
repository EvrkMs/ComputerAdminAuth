using System;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.TelegramAuth.Interface;
using Auth.TelegramAuth.Raw;

namespace Auth.Application.UseCases.Telegram;

public class BindTelegramCommand
{
    private readonly ITelegramRepository _telegramRepo;
    private readonly IUserRepository _userRepo;
    private readonly ITelegramAuthService _tg;
    private readonly IUnitOfWork _unitOfWork;

    public BindTelegramCommand(
        IUnitOfWork unitOfWork,
        ITelegramRepository telegramRepo,
        IUserRepository userRepo,
        ITelegramAuthService tg)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _telegramRepo = telegramRepo ?? throw new ArgumentNullException(nameof(telegramRepo));
        _userRepo = userRepo ?? throw new ArgumentNullException(nameof(userRepo));
        _tg = tg ?? throw new ArgumentNullException(nameof(tg));
    }

    public async Task<Result> ExecuteAsync(
        Guid currentUserId,
        TelegramRawData dto,
        CancellationToken ct = default)
    {
        if (!_tg.VerifyWidget(dto, out var err))
            return Result.Fail(err ?? "bad signature");

        var existingByTg = await _telegramRepo.GetByTelegramIdAsync(dto.Id, ct);
        if (existingByTg is not null && existingByTg.UserId != currentUserId)
            return Result.Fail("Этот Telegram уже привязан к другому аккаунту");

        var user = await _userRepo.GetByIdAsync(currentUserId, ct);
        if (user is null || !user.IsActive)
            return Result.Fail("Пользователь не найден или не активен");

        var normalized = Normalize(dto);
        var now = DateTime.UtcNow;

        try
        {
            await _unitOfWork.ExecuteInTransactionAsync(async innerCt =>
            {
                var myTg = await _telegramRepo.GetByUserIdForUpdateAsync(currentUserId, innerCt);
                if (myTg is null)
                {
                    var entity = new TelegramEntity
                    {
                        Id = Guid.NewGuid(),
                        TelegramId = dto.Id,
                        FirstName = normalized.FirstName ?? string.Empty,
                        LastName = normalized.LastName ?? string.Empty,
                        Username = normalized.Username,
                        PhotoUrl = normalized.PhotoUrl ?? string.Empty,
                        UserId = currentUserId,
                        BoundAt = now,
                        LastLoginDate = now
                    };

                    await _telegramRepo.AddAsync(entity, innerCt);
                }
                else
                {
                    if (normalized.FirstName is not null)
                        myTg.FirstName = normalized.FirstName;
                    if (normalized.LastName is not null)
                        myTg.LastName = normalized.LastName;
                    if (!string.IsNullOrEmpty(normalized.Username))
                        myTg.Username = normalized.Username;
                    if (normalized.PhotoUrl is not null)
                        myTg.PhotoUrl = normalized.PhotoUrl;
                    myTg.LastLoginDate = now;

                    await _telegramRepo.UpdateAsync(myTg, innerCt);
                }

                await _unitOfWork.SaveChangesAsync(innerCt);
            }, ct);

            return Result.Ok();
        }
        catch (Exception ex)
        {
            return Result.Fail($"Не удалось сохранить привязку: {ex.Message}");
        }
    }

    private static NormalizedTelegramData Normalize(TelegramRawData dto)
    {
        static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        var username = Clean(dto.Username) ?? string.Empty;
        if (username.StartsWith("@", StringComparison.Ordinal))
            username = username[1..];
        username = username.ToLowerInvariant();

        return new NormalizedTelegramData(
            FirstName: Clean(dto.FirstName),
            LastName: Clean(dto.LastName),
            Username: username,
            PhotoUrl: Clean(dto.PhotoUrl));
    }

    private sealed record NormalizedTelegramData(string? FirstName, string? LastName, string Username, string? PhotoUrl);
}
