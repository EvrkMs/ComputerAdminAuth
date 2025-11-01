using System.ComponentModel.DataAnnotations;

namespace Auth.Domain.Entities;

public class TelegramEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public long TelegramId { get; set; }

    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string PhotoUrl { get; set; } = string.Empty;

    public Guid UserId { get; set; }
    [Required]
    public UserEntity User { get; set; } = null!;

    public DateTime BoundAt { get; set; } = DateTime.UtcNow;
    public DateTime LastLoginDate { get; set; } = DateTime.UtcNow;
}
