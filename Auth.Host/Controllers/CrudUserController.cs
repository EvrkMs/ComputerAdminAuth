using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Auth.Application;
using Auth.Application.UseCases.Users;
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace Auth.Host.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "Root")]
public class CrudUserController : ControllerBase
{
    private readonly IUserAdministrationService _users;

    public CrudUserController(IUserAdministrationService users)
    {
        _users = users;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<UserListItemDto>>> GetAll(
        [FromQuery] string? query,
        [FromQuery] UserStatus? status,
        CancellationToken ct = default)
    {
        var items = await _users.ListAsync(query, status, ct);
        return Ok(items);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<UserListItemDto>> GetById(Guid id, CancellationToken ct = default)
    {
        var user = await _users.GetAsync(id, ct);
        return user is null ? NotFound() : Ok(user);
    }

    [HttpGet("roles")]
    public async Task<ActionResult<IEnumerable<RoleDto>>> GetRoles(CancellationToken ct = default)
    {
        var roles = await _users.ListRolesAsync(ct);
        return Ok(roles);
    }

    [HttpPost]
    public async Task<ActionResult<UserListItemDto>> Create([FromBody] CreateUserRequest req, CancellationToken ct = default)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var input = new CreateUserInput(
            UserName: req.UserName.Trim(),
            Password: req.Password,
            FullName: req.FullName.Trim(),
            Status: req.Status ?? UserStatus.Active,
            Roles: req.Roles ?? Array.Empty<string>());

        var result = await _users.CreateAsync(input, ct);
        if (!result.Success)
            return Failure(result);

        return CreatedAtAction(nameof(GetById), new { id = result.Value!.Id }, result.Value);
    }

    [HttpPut("{id:guid}")]
    public async Task<ActionResult<UserListItemDto>> Update(Guid id, [FromBody] UpdateUserRequest req, CancellationToken ct = default)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var input = new UpdateUserInput(
            FullName: req.FullName,
            PhoneNumber: req.PhoneNumber,
            Status: req.Status,
            Roles: req.Roles);

        var result = await _users.UpdateAsync(id, input, ct);
        if (!result.Success)
            return Failure(result);

        return Ok(result.Value);
    }

    [HttpPost("{id:guid}/password")]
    public async Task<IActionResult> ChangePassword(Guid id, [FromBody] ChangePasswordRequest req, CancellationToken ct = default)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var result = await _users.ChangePasswordAsync(
            id,
            new ChangePasswordInput(req.NewPassword, req.RequireChangeOnNextLogin ?? true),
            ct);

        if (!result.Success)
            return Failure(result);

        return NoContent();
    }

    [HttpPost("roles")]
    public async Task<ActionResult<RoleDto>> CreateRole([FromBody] CreateRoleRequest req, CancellationToken ct = default)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var result = await _users.CreateRoleAsync(new CreateRoleInput(req.Name), ct);
        if (!result.Success)
            return Failure(result);

        return CreatedAtAction(nameof(GetRoles), new { }, result.Value);
    }

    [HttpPut("roles/{id:guid}")]
    public async Task<ActionResult<RoleDto>> UpdateRole(Guid id, [FromBody] UpdateRoleRequest req, CancellationToken ct = default)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var result = await _users.UpdateRoleAsync(id, new UpdateRoleInput(req.Name), ct);
        if (!result.Success)
            return Failure(result);

        return Ok(result.Value);
    }

    [HttpDelete("roles/{id:guid}")]
    public async Task<IActionResult> DeleteRole(Guid id, CancellationToken ct = default)
    {
        var result = await _users.DeleteRoleAsync(id, ct);
        if (!result.Success)
            return Failure(result);

        return NoContent();
    }

    private ActionResult<T> Failure<T>(OperationResult<T> result)
    {
        if (result.ValidationErrors is not null)
        {
            AppendValidationErrors(result.ValidationErrors);
            return ValidationProblem(ModelState);
        }

        if (string.Equals(result.Error, "not_found", StringComparison.OrdinalIgnoreCase))
            return NotFound();

        return Problem(detail: result.Error ?? "Операция не выполнена.");
    }

    private ActionResult Failure(OperationResult result)
    {
        if (result.ValidationErrors is not null)
        {
            AppendValidationErrors(result.ValidationErrors);
            return ValidationProblem(ModelState);
        }

        if (string.Equals(result.Error, "not_found", StringComparison.OrdinalIgnoreCase))
            return NotFound();

        return Problem(detail: result.Error ?? "Операция не выполнена.");
    }

    private void AppendValidationErrors(IReadOnlyDictionary<string, string[]> errors)
    {
        foreach (var (key, messages) in errors)
        {
            foreach (var message in messages)
                ModelState.AddModelError(key, message);
        }
    }
}

public record CreateUserRequest
{
    [Required, MinLength(3)]
    public string UserName { get; init; } = string.Empty;

    [Required, MinLength(6)]
    public string Password { get; init; } = string.Empty;

    [Required, MinLength(2)]
    public string FullName { get; init; } = string.Empty;

    public UserStatus? Status { get; init; } = UserStatus.Active;

    public IReadOnlyCollection<string>? Roles { get; init; }
}

public record UpdateUserRequest
{
    [MinLength(2)]
    public string? FullName { get; init; }
    public string? PhoneNumber { get; init; }
    public UserStatus? Status { get; init; }
    public IReadOnlyCollection<string>? Roles { get; init; }
}

public record ChangePasswordRequest
{
    [Required, MinLength(6)]
    public string NewPassword { get; init; } = string.Empty;

    public bool? RequireChangeOnNextLogin { get; init; } = true;
}

public record CreateRoleRequest
{
    [Required, MinLength(2)]
    [MaxLength(64)]
    public string Name { get; init; } = string.Empty;
}

public record UpdateRoleRequest
{
    [Required, MinLength(2)]
    [MaxLength(64)]
    public string Name { get; init; } = string.Empty;
}
