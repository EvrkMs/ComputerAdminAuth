using Auth.Domain.Entities;

namespace Auth.Application.Interfaces;

public interface ISessionRepository
{
    Task<UserSession?> GetAsync(Guid id, CancellationToken ct = default);
    Task<UserSession?> GetByReferenceAsync(string referenceId, CancellationToken ct = default);
    Task<UserSession?> GetActiveByReferenceAsync(string referenceId, CancellationToken ct = default);
    Task<UserSession?> GetByAuthorizationIdAsync(string authorizationId, CancellationToken ct = default);
    Task<UserSession> AddAsync(UserSession session, CancellationToken ct = default);
    Task UpdateAsync(UserSession session, CancellationToken ct = default);
    Task DeleteAsync(UserSession session, CancellationToken ct = default);
    Task<int> DeleteRevokedAsync(CancellationToken ct = default);
    IAsyncEnumerable<UserSession> ListByUserAsync(Guid userId, bool onlyActive = true, CancellationToken ct = default);
}
