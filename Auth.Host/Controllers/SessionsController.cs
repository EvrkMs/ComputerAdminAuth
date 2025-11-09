using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using System;
using System.Security.Claims;

namespace Auth.Host.Controllers;

[ApiController]
[Route("api/sessions")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public class SessionsController : ControllerBase
{
    private readonly ISessionRepository _repo;
    private readonly ISessionService _sessions;

    public SessionsController(ISessionRepository repo, ISessionService sessions)
    {
        _repo = repo;
        _sessions = sessions;
    }

    private bool TryGetUserId(out Guid userId)
    {
        userId = default;
        var sub = User.FindFirstValue("sub")
            ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? User.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        return Guid.TryParse(sub, out userId);
    }

    [HttpGet]
    [Authorize(Policy = "ApiRead")]
    public async Task<ActionResult<IEnumerable<UserSessionDto>>> List([FromQuery] bool all = false, CancellationToken ct = default)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();
        var currentSid = GetCurrentSid();
        var result = new List<UserSessionDto>();
        await foreach (var s in _repo.ListByUserAsync(userId, onlyActive: !all, ct: ct))
            result.Add(ToDto(s, currentSid));
        return Ok(result);
    }

    [HttpGet("current")]
    [Authorize(Policy = "ApiRead")]
    public async Task<ActionResult<UserSessionDto>> Current(CancellationToken ct = default)
    {
        var sid = GetCurrentSid();
        if (string.IsNullOrWhiteSpace(sid))
            return NotFound(new { error = "no_sid" });
        var s = await _repo.GetByReferenceAsync(sid, ct);
        return s is null ? NotFound() : Ok(ToDto(s, sid));
    }

    [HttpPost("revoke-all")]
    [Authorize(Policy = "ApiWrite")]
    public async Task<IActionResult> RevokeAll(CancellationToken ct = default)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();
        // Do not revoke the session from which this action is performed
        var currentSid = GetCurrentSid();
        var count = 0;
        await foreach (var s in _repo.ListByUserAsync(userId, onlyActive: true, ct: ct))
        {
            var sid = s.ReferenceId;
            if (!string.IsNullOrWhiteSpace(currentSid) && string.Equals(sid, currentSid, StringComparison.OrdinalIgnoreCase))
                continue;
            if (await _sessions.RevokeAsync(sid, reason: "user_revoked_all", by: userId.ToString(), ct))
                count++;
        }
        return Ok(new { revoked = count });
    }

    [HttpPost("{id:guid}/revoke")]
    [Authorize(Policy = "ApiWrite")]
    public async Task<IActionResult> RevokeOne(Guid id, CancellationToken ct = default)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();
        var s = await _repo.GetAsync(id, ct);
        if (s is null) return NotFound();
        if (s.UserId != userId) return Forbid();
        var revoked = await _sessions.RevokeAsync(s.ReferenceId, reason: "user_revoked", by: userId.ToString(), ct);
        return revoked ? NoContent() : Conflict(new { error = "already_revoked" });
    }

    private string? GetCurrentSid() => ExtractSidFromContext(HttpContext);

    private static string? ExtractSidFromContext(HttpContext context)
    {
        if (context.Items.TryGetValue("sid", out var item) && item is string sidFromMiddleware && !string.IsNullOrWhiteSpace(sidFromMiddleware))
            return sidFromMiddleware;

        return context.User.FindFirstValue("sid");
    }

    private static UserSessionDto ToDto(UserSession s, string? currentSid = null) => new()
    {
        Id = s.Id,
        ReferenceId = s.ReferenceId,
        Device = s.Device,
        ClientId = s.ClientId,
        CreatedAt = s.CreatedAt,
        LastSeenAt = s.LastSeenAt,
        ExpiresAt = s.ExpiresAt,
        Revoked = s.Revoked,
        RevokedAt = s.RevokedAt,
        IpAddress = s.IpAddress,
        UserAgent = s.UserAgent,
        IsCurrent = !string.IsNullOrWhiteSpace(currentSid) && string.Equals(s.ReferenceId, currentSid, StringComparison.OrdinalIgnoreCase)
    };
}

public sealed record UserSessionDto
{
    public Guid Id { get; init; }
    public string ReferenceId { get; init; } = string.Empty;
    public string? ClientId { get; init; }
    public string? Device { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime? LastSeenAt { get; init; }
    public DateTime? ExpiresAt { get; init; }
    public bool Revoked { get; init; }
    public DateTime? RevokedAt { get; init; }
    public bool IsCurrent { get; init; }
}
