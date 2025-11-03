using System.ComponentModel.DataAnnotations;

namespace Auth.Domain.Entities;

/// <summary>
/// Links a browser session to the OpenIddict authorization identifiers created through it.
/// Enables cascading revocation of all tokens issued under that session.
/// </summary>
public sealed class UserSessionAuthorization
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid SessionId { get; set; }

    [Required]
    [MaxLength(128)]
    public string AuthorizationId { get; set; } = string.Empty;

    [MaxLength(128)]
    public string? ClientId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public UserSession Session { get; set; } = default!;
}
