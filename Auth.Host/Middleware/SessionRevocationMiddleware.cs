using Auth.Application.Interfaces;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace Auth.Host.Middleware;

public class SessionRevocationMiddleware
{
    private readonly RequestDelegate _next;

    public SessionRevocationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ISessionService sessions)
    {
        // Enforce for API routes or any request carrying Authorization header
        var hasAuthHeader = context.Request.Headers.ContainsKey("Authorization");
        var isApi = context.Request.Path.StartsWithSegments("/api");
        if ((isApi || hasAuthHeader) && context.User?.Identity?.IsAuthenticated == true)
        {
            var sid = context.User.FindFirst("sid")?.Value;
            // For any user token (has subject), sid is required and must be active.
            var subject = context.User.FindFirst(OpenIddictConstants.Claims.Subject)?.Value
                          ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                          ?? context.User.FindFirst("sub")?.Value;
            var isUserToken = !string.IsNullOrEmpty(subject);
            if (isUserToken && string.IsNullOrEmpty(sid))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"session_required\"}");
                return;
            }
            if (!string.IsNullOrEmpty(sid))
            {
                context.Items["sid"] = sid;
                var active = await sessions.IsActiveAsync(sid);
                if (!active)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"session_revoked\"}");
                    return;
                }
            }
        }

        await _next(context);
    }
}

public static class SessionRevocationMiddlewareExtensions
{
    public static IApplicationBuilder UseSessionRevocationValidation(this IApplicationBuilder app)
        => app.UseMiddleware<SessionRevocationMiddleware>();
}
