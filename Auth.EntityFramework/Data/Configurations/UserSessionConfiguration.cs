using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.Data.Configurations;

internal class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.ToTable("user_sessions");

        builder.HasKey(s => s.Id);

        builder.Property(s => s.UserId).IsRequired();

        builder.Property(s => s.ClientId).HasMaxLength(200);
        builder.Property(s => s.Device).HasMaxLength(200);
        builder.Property(s => s.UserAgent).HasMaxLength(500);
        builder.Property(s => s.IpAddress).HasMaxLength(100);
        builder.Property(s => s.RevokedBy).HasMaxLength(200);
        builder.Property(s => s.RevocationReason).HasMaxLength(500);
        builder.Property(s => s.AuthorizationId).HasMaxLength(200);

        builder.HasIndex(s => new { s.UserId, s.Revoked });
        builder.HasIndex(s => s.AuthorizationId);
        builder.HasIndex(s => s.ClientId);
        builder.HasIndex(s => s.CreatedAt);
    }
}
