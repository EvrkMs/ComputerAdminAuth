using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Auth.Host.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Host.Middleware;

/// <summary>
/// Captures Cloudflare-specific client IP headers and normalises them into the standard forwarding chain.
/// </summary>
public sealed class CloudflareTrueClientIpMiddleware
{
    private readonly RequestDelegate _next;
    private readonly CloudflareOptions _options;
    private readonly IReadOnlyList<IpRange> _trustedRanges;
    private readonly ILogger<CloudflareTrueClientIpMiddleware> _logger;

    public CloudflareTrueClientIpMiddleware(
        RequestDelegate next,
        IOptions<CloudflareOptions> options,
        ILogger<CloudflareTrueClientIpMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _options = options.Value ?? new CloudflareOptions();
        _trustedRanges = BuildRangeList(_options.TrustedNetworks, logger);
        if (_options.Enabled && _trustedRanges.Count == 0)
        {
            _logger.LogWarning("Cloudflare support is enabled but no trusted networks are configured.");
        }
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Enabled || _trustedRanges.Count == 0)
        {
            await _next(context);
            return;
        }

        if (!IsTrustedSource(context.Connection.RemoteIpAddress))
        {
            await _next(context);
            return;
        }

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

    private bool IsTrustedSource(IPAddress? source)
    {
        if (source is null)
            return false;

        foreach (var range in _trustedRanges)
            if (range.Contains(source))
                return true;

        _logger.LogDebug("Request from {Ip} skipped Cloudflare middleware because it is not in the trusted range list.", source);
        return false;
    }

    private IPAddress? ExtractClientIp(HttpContext context)
    {
        if (TryParseIp(context.Request.Headers["CF-Connecting-IP"], out var cfIp))
            return cfIp;

        if (_options.AllowTrueClientIpHeader &&
            TryParseIp(context.Request.Headers["True-Client-IP"], out var trueClientIp))
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

    private static IReadOnlyList<IpRange> BuildRangeList(string[]? entries, ILogger logger)
    {
        if (entries is null || entries.Length == 0)
            return Array.Empty<IpRange>();

        var ranges = new List<IpRange>();
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry))
                continue;

            if (IpRange.TryParse(entry, out var range))
            {
                ranges.Add(range);
            }
            else
            {
                logger.LogWarning("Failed to parse Cloudflare trusted network entry '{Entry}'.", entry);
            }
        }

        return ranges;
    }

    private sealed record IpRange(IPAddress Network, int? PrefixLength)
    {
        public static bool TryParse(string value, out IpRange range)
        {
            range = default!;
            var trimmed = value.Trim();
            if (trimmed.Contains('/'))
            {
                var parts = trimmed.Split('/', 2, StringSplitOptions.TrimEntries);
                if (parts.Length != 2)
                    return false;

                if (!IPAddress.TryParse(parts[0], out var network))
                    return false;

                if (!int.TryParse(parts[1], out var prefix))
                    return false;

                if (!IsValidPrefix(network, prefix))
                    return false;

                range = new IpRange(network, prefix);
                return true;
            }

            if (!IPAddress.TryParse(trimmed, out var single))
                return false;

            range = new IpRange(single, null);
            return true;
        }

        public bool Contains(IPAddress? candidate)
        {
            if (candidate is null)
                return false;

            if (PrefixLength is null)
                return Normalize(candidate).Equals(Normalize(Network));

            var normalizedCandidate = Normalize(candidate);
            var normalizedNetwork = Normalize(Network);

            if (normalizedCandidate.AddressFamily != normalizedNetwork.AddressFamily)
                return false;

            var candidateBytes = normalizedCandidate.GetAddressBytes();
            var networkBytes = normalizedNetwork.GetAddressBytes();
            var prefix = PrefixLength.Value;

            var fullBytes = prefix / 8;
            var remainder = prefix % 8;

            for (var i = 0; i < fullBytes; i++)
            {
                if (candidateBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainder == 0)
                return true;

            var mask = (byte)~(0xFF >> remainder);
            return (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }

        private static bool IsValidPrefix(IPAddress address, int prefix)
        {
            return address.AddressFamily switch
            {
                AddressFamily.InterNetwork => prefix is >= 0 and <= 32,
                AddressFamily.InterNetworkV6 => prefix is >= 0 and <= 128,
                _ => false
            };
        }

        private static IPAddress Normalize(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
                return address.MapToIPv4();

            return address;
        }
    }
}
