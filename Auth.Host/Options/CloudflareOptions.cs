using System;

namespace Auth.Host.Options;

/// <summary>
/// Configuration for Cloudflare-aware client IP handling.
/// </summary>
public sealed class CloudflareOptions
{
    /// <summary>
    /// Enables Cloudflare header normalization middleware.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// List of IPv4/IPv6 addresses or CIDR ranges that are considered trusted Cloudflare egress nodes.
    /// Only requests originating from these networks will have Cloudflare headers applied.
    /// </summary>
    public string[] TrustedNetworks { get; set; } = Array.Empty<string>();

    /// <summary>
    /// When true, honors the True-Client-IP header in addition to CF-Connecting-IP.
    /// Some providers expose this header only in specific regions; keep it disabled otherwise.
    /// </summary>
    public bool AllowTrueClientIpHeader { get; set; }
}
