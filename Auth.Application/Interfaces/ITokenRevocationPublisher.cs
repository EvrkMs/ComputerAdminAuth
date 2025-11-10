namespace Auth.Application.Interfaces;

public interface ITokenRevocationPublisher
{
    Task PublishAsync(IEnumerable<RevokedTokenNotification> notifications, CancellationToken ct = default);
}

public sealed record RevokedTokenNotification(
    string? TokenId,
    string? AuthorizationId,
    string? SessionReferenceId,
    string Reason,
    DateTime TimestampUtc,
    string? ClientId = null,
    int? TokenCount = null);
