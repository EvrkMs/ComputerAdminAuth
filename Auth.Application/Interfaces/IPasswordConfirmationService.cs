using System;

namespace Auth.Application.Interfaces;

// Auth.Application/Interfaces/IPasswordConfirmationService.cs
public interface IPasswordConfirmationService
{
    TimeSpan TokenLifetime { get; }

    Task<string> CreateTokenAsync(Guid userId, string purpose, CancellationToken ct = default);

    Task<bool> ValidateTokenAsync(Guid userId, string purpose, string token, CancellationToken ct = default);
}
