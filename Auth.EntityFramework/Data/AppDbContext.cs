using Auth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Data;

public class AppDbContext(DbContextOptions<AppDbContext> opt)
    : IdentityDbContext<UserEntity, IdentityRole<Guid>, Guid>(opt)
{
    public DbSet<TelegramEntity> TelegramEntities => Set<TelegramEntity>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);

        modelBuilder.UseOpenIddict();
        base.OnModelCreating(modelBuilder);
    }
}
