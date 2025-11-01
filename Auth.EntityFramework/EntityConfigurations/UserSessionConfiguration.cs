using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.EntityConfigurations;

/// <summary>
/// Centralizes storage-specific rules for <see cref="UserSession"/> so all services rely on the same schema.
/// </summary>
internal sealed class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.HasIndex(x => x.ReferenceId).IsUnique();
        builder.Property(x => x.ReferenceId).HasMaxLength(64).IsRequired();
        builder.Property(x => x.SecretHash).HasMaxLength(256).IsRequired();
        builder.Property(x => x.SecretSalt).HasMaxLength(128).IsRequired();
    }
}
