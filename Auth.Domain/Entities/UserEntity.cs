using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities;

public class UserEntity : IdentityUser<Guid>
{
    public string FullName { get; set; } = string.Empty;
    public UserStatus Status { get; set; } = UserStatus.Active;

    public DateTime CreatedAt { get; private set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    public bool IsActive => Status == UserStatus.Active;

    public bool MustChangePassword { get; set; } = true;
}

public enum UserStatus
{
    Active = 0,
    Inactive = 1,
}
