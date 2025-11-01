using Auth.Application.Interfaces;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Auth.Infrastructure.Data;

// Auth.Infrastructure/Data/UnitOfWork.cs
public class UnitOfWork : IUnitOfWork
{
    private readonly AppDbContext _context;

    public UnitOfWork(AppDbContext context) => _context = context;

    public Task<int> SaveChangesAsync(CancellationToken ct = default)
        => _context.SaveChangesAsync(ct);

    public async Task<ITransaction> BeginTransactionAsync(CancellationToken ct = default)
    {
        var transaction = await _context.Database.BeginTransactionAsync(ct);
        return new EfTransaction(transaction);
    }

    public Task ExecuteInTransactionAsync(Func<CancellationToken, Task> work, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(work);

        var strategy = _context.Database.CreateExecutionStrategy();
        return strategy.ExecuteAsync(async () =>
        {
            await using var transaction = await _context.Database.BeginTransactionAsync(ct);
            try
            {
                await work(ct);
                await transaction.CommitAsync(ct);
            }
            catch
            {
                try
                {
                    await transaction.RollbackAsync(ct);
                }
                catch
                {
                    // ignore rollback errors, original exception will be rethrown
                }

                throw;
            }
        });
    }
}

// Обертка для EF транзакции
internal class EfTransaction : ITransaction
{
    private readonly IDbContextTransaction _transaction;

    public EfTransaction(IDbContextTransaction transaction)
        => _transaction = transaction;

    public Task CommitAsync(CancellationToken ct = default)
        => _transaction.CommitAsync(ct);

    public Task RollbackAsync(CancellationToken ct = default)
        => _transaction.RollbackAsync(ct);

    public void Dispose() => _transaction.Dispose();
}
