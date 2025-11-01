using System.ComponentModel.DataAnnotations;

namespace Auth.Domain.Entities;

public class UserSession
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Public handle returned to clients (sid claim/cookie metadata). High-entropy, opaque.
    /// </summary>
    [Required]
    [MaxLength(64)]
    public string ReferenceId { get; set; } = string.Empty;

    /// <summary>
    /// Salted hash of the confidential browser secret. Never store the raw secret.
    /// </summary>
    [Required]
    [MaxLength(256)]
    public string SecretHash { get; set; } = string.Empty;

    /// <summary>
    /// Salt used to derive <see cref="SecretHash"/>. Stored per-session to enable rotation.
    /// </summary>
    [Required]
    [MaxLength(128)]
    public string SecretSalt { get; set; } = string.Empty;

    public DateTime SecretCreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? SecretExpiresAt { get; set; }

    [Required]
    public Guid UserId { get; set; }

    // OIDC client id that initiated the session (optional)
    public string? ClientId { get; set; }

    // Metadata for UX/admin
    public string? Device { get; set; }
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastSeenAt { get; set; }
    public DateTime? ExpiresAt { get; set; }

    // Revocation info
    public bool Revoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
    public string? RevocationReason { get; set; }

    // Link to OpenIddict authorization (for precise token revocation)
    public string? AuthorizationId { get; set; }
}
