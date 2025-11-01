using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Repositories;

public class SessionRepository(AppDbContext db) : ISessionRepository
{
    public async Task<UserSession?> GetAsync(Guid id, CancellationToken ct = default)
        => await db.UserSessions.FirstOrDefaultAsync(s => s.Id == id, ct);

    public async Task<UserSession?> GetByReferenceAsync(string referenceId, CancellationToken ct = default)
        => await db.UserSessions.FirstOrDefaultAsync(s => s.ReferenceId == referenceId, ct);

    public async Task<UserSession?> GetActiveByReferenceAsync(string referenceId, CancellationToken ct = default)
        => await db.UserSessions.FirstOrDefaultAsync(s =>
            s.ReferenceId == referenceId &&
            !s.Revoked &&
            (s.ExpiresAt == null || s.ExpiresAt > DateTime.UtcNow),
            ct);

    public async Task<UserSession> AddAsync(UserSession session, CancellationToken ct = default)
    {
        await db.UserSessions.AddAsync(session, ct);
        return session;
    }

    public Task UpdateAsync(UserSession session, CancellationToken ct = default)
    {
        db.UserSessions.Update(session);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(UserSession session, CancellationToken ct = default)
    {
        db.UserSessions.Remove(session);
        return Task.CompletedTask;
    }

    public async Task<int> DeleteRevokedAsync(CancellationToken ct = default)
    {
        var revoked = await db.UserSessions
            .Where(s => s.Revoked)
            .ToListAsync(ct);
        if (revoked.Count == 0)
            return 0;

        db.UserSessions.RemoveRange(revoked);
        return revoked.Count;
    }

    public async IAsyncEnumerable<UserSession> ListByUserAsync(Guid userId, bool onlyActive = true, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        var query = db.UserSessions.AsNoTracking().Where(s => s.UserId == userId);
        if (onlyActive)
            query = query.Where(s => !s.Revoked && (s.ExpiresAt == null || s.ExpiresAt > DateTime.UtcNow));

        await foreach (var s in query.OrderByDescending(s => s.CreatedAt).AsAsyncEnumerable().WithCancellation(ct))
            yield return s;
    }
}
