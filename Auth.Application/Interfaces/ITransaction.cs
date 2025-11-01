namespace Auth.Application.Interfaces;

// Auth.Application/Interfaces/ITransaction.cs
public interface ITransaction : IDisposable
{
    Task CommitAsync(CancellationToken ct = default);
    Task RollbackAsync(CancellationToken ct = default);
}