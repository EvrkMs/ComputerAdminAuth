using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.Data.Configurations;

internal class UserConfiguration : IEntityTypeConfiguration<UserEntity>
{
    public void Configure(EntityTypeBuilder<UserEntity> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.FullName)
            .HasMaxLength(200);

        builder.Property(u => u.Status)
            .HasConversion<string>()
            .IsRequired();
    }
}
