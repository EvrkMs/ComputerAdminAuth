// Namespace: Auth.TelegramAuth (библиотека)
namespace Auth.TelegramAuth.Options;

public sealed class TelegramAuthOptions
{
    public required string BotToken { get; init; }
    public int AllowedClockSkewSeconds { get; init; } = 300; // 5 мин по умолчанию
}
