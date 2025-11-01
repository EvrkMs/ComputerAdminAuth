using Microsoft.AspNetCore.Mvc;

namespace Auth.Host.Services;

public sealed record SessionGuardResult(bool Ok, IActionResult? Action);
