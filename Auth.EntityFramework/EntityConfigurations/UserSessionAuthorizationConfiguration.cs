using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.EntityConfigurations;

internal sealed class UserSessionAuthorizationConfiguration : IEntityTypeConfiguration<UserSessionAuthorization>
{
    public void Configure(EntityTypeBuilder<UserSessionAuthorization> builder)
    {
        builder.Property(x => x.AuthorizationId).HasMaxLength(128).IsRequired();
        builder.Property(x => x.ClientId).HasMaxLength(128);
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.HasIndex(x => x.AuthorizationId).IsUnique();
        builder.HasIndex(x => new { x.SessionId, x.AuthorizationId }).IsUnique();

        builder.HasOne(x => x.Session)
            .WithMany(s => s.Authorizations)
            .HasForeignKey(x => x.SessionId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
