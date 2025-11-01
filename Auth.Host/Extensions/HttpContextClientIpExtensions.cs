using System.Net;

namespace Auth.Host.Extensions;

public static class HttpContextClientIpExtensions
{
    public static string? GetRealClientIp(this HttpContext http)
    {
        if (http.Items.TryGetValue("cf:true_client_ip", out var cfItem) && cfItem is string cfStored)
            return cfStored;

        if (TryParsePublicIp(http.Request.Headers["CF-Connecting-IP"], out var cfHeader))
            return cfHeader;

        if (TryParsePublicIp(http.Request.Headers["True-Client-IP"], out var trueClient))
            return trueClient;

        // After UseForwardedHeaders, RemoteIpAddress should already be client IP
        var ip = http.Connection.RemoteIpAddress;
        if (ip is not null && !IsPrivateOrLocal(ip))
            return ip.ToString();

        // Fallbacks: trust only for display/analytics (not for security decisions)
        // Prefer first entry from X-Forwarded-For
        var xff = http.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
        {
            var first = xff.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                           .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(first) && IPAddress.TryParse(first, out var parsed) && !IsPrivateOrLocal(parsed))
                return parsed.ToString();
        }

        // Some proxies pass X-Real-IP
        var xri = http.Request.Headers["X-Real-IP"].ToString();
        if (!string.IsNullOrWhiteSpace(xri) && IPAddress.TryParse(xri, out var real) && !IsPrivateOrLocal(real))
            return real.ToString();

        return ip?.ToString();
    }

    private static bool TryParsePublicIp(string? headerValue, out string? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(headerValue))
            return false;

        var firstToken = headerValue
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        if (string.IsNullOrWhiteSpace(firstToken))
            return false;

        if (!IPAddress.TryParse(firstToken, out var ip) || IsPrivateOrLocal(ip))
            return false;

        result = ip.ToString();
        return true;
    }

    private static bool IsPrivateOrLocal(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return true;

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12 => 172.16.0.0 - 172.31.255.255
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 127.0.0.0/8 already covered by IsLoopback but keep explicit
            if (bytes[0] == 127) return true;
        }
        else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal)
                return true;
            // Unique local addresses fc00::/7
            var bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC) return true;
        }

        return false;
    }
}
