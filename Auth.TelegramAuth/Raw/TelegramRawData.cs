// Namespace: Auth.TelegramAuth (библиотека)
namespace Auth.TelegramAuth.Raw;

public sealed class TelegramRawData // заменяем record struct
{
    public required long Id { get; init; }
    public string? Username { get; init; }
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? PhotoUrl { get; init; }
    public required long AuthDate { get; init; }
    public required string Hash { get; init; }
}
