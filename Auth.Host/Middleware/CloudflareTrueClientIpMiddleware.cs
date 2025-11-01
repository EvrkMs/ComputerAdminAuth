using System.Net;

namespace Auth.Host.Middleware;

/// <summary>
/// Captures Cloudflare-specific client IP headers and normalises them into the standard forwarding chain.
/// </summary>
public sealed class CloudflareTrueClientIpMiddleware
{
    private readonly RequestDelegate _next;

    public CloudflareTrueClientIpMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var clientIp = ExtractClientIp(context);
        if (clientIp is not null)
        {
            var clientIpString = clientIp.ToString();
            context.Items["cf:true_client_ip"] = clientIpString;
            context.Connection.RemoteIpAddress = clientIp;

            var forwardedValue = context.Request.Headers["X-Forwarded-For"].ToString();
            if (string.IsNullOrWhiteSpace(forwardedValue) ||
                !forwardedValue.Contains(clientIpString, StringComparison.OrdinalIgnoreCase))
            {
                var newForward = string.IsNullOrWhiteSpace(forwardedValue)
                    ? clientIpString
                    : $"{clientIpString}, {forwardedValue}";
                context.Request.Headers["X-Forwarded-For"] = newForward;
            }
        }

        await _next(context);
    }

    private static IPAddress? ExtractClientIp(HttpContext context)
    {
        if (TryParseIp(context.Request.Headers["CF-Connecting-IP"], out var cfIp))
            return cfIp;

        if (TryParseIp(context.Request.Headers["True-Client-IP"], out var trueClientIp))
            return trueClientIp;

        return null;
    }

    private static bool TryParseIp(string? value, out IPAddress? address)
    {
        address = null;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var candidate = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                             .FirstOrDefault();
        if (candidate is null)
            return false;

        if (!IPAddress.TryParse(candidate, out var parsed))
            return false;

        address = parsed;
        return true;
    }
}
