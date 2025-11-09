using Auth.Application.UseCases;
using Auth.Host.Extensions;
using Auth.Host.Middleware;
using Auth.Host.Options;
using Auth.Host.ProfileService;
using Auth.Host.Services.Cors;
using Auth.Infrastructure;
using Auth.Infrastructure.Seeder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var cfg = builder.Configuration;

services.Configure<CloudflareOptions>(options =>
{
    cfg.GetSection("Cloudflare").Bind(options);

    var envToggle = cfg.GetValue<bool?>("USE_CLOUDFLARE")
        ?? cfg.GetValue<bool?>("UseCloudflare");
    if (envToggle.HasValue)
        options.Enabled = envToggle.Value;

    var envTrueClient = cfg.GetValue<bool?>("CLOUDFLARE_ALLOW_TRUE_CLIENT_IP")
        ?? cfg.GetValue<bool?>("USE_TRUE_CLIENT_IP")
        ?? cfg.GetValue<bool?>("USE_TRUE_CLIENT_IP_HEADER");
    if (envTrueClient.HasValue)
        options.AllowTrueClientIpHeader = envTrueClient.Value;

    var envTrusted = cfg["CLOUDFLARE_TRUSTED_PROXIES"];
    if (!string.IsNullOrWhiteSpace(envTrusted))
    {
        var combined = options.TrustedNetworks ?? Array.Empty<string>();
        options.TrustedNetworks = combined
            .Concat(SplitList(envTrusted))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
});

services.Configure<SessionCookieOptions>(options =>
{
    cfg.GetSection("SessionCookie").Bind(options);

    var envDomain = cfg["SESSION_COOKIE_DOMAIN"];
    if (!string.IsNullOrWhiteSpace(envDomain))
        options.Domain = envDomain;

    var envPath = cfg["SESSION_COOKIE_PATH"];
    if (!string.IsNullOrWhiteSpace(envPath))
        options.Path = envPath;

    var envSameSite = cfg["SESSION_COOKIE_SAMESITE"];
    if (!string.IsNullOrWhiteSpace(envSameSite) && Enum.TryParse<SameSiteMode>(envSameSite, true, out var parsed))
        options.SameSite = parsed;

    var envSecure = cfg["SESSION_COOKIE_SECURE"];
    if (!string.IsNullOrWhiteSpace(envSecure) && bool.TryParse(envSecure, out var secure))
        options.Secure = secure;

    if (string.IsNullOrWhiteSpace(options.Path))
        options.Path = "/";
});

builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
builder.Logging.AddFilter("Npgsql", LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore.Cors", LogLevel.Debug);

// Bind Kestrel to HTTPS on 5001 with an in-memory self-signed certificate
// Kestrel TLS: load shared cert from /tls (or generate and persist)
builder.WebHost.UseKestrel(o =>
{
    o.ListenAnyIP(5001, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = EphemeralCert.Create();
        });
    });
});
// Service wiring lives in Extensions/AuthHostServiceCollectionExtensions.cs
services.AddAuthHostServices(cfg);

var app = builder.Build();

// Request pipeline composition lives in Extensions/AuthHostApplicationExtensions.cs
app.UseAuthHostPipeline(cfg);

// Migrations + Seed
using (var scope = app.Services.CreateScope())
{
    var sp = scope.ServiceProvider;
    await sp.ApplyMigrationsAndSeedAsync(app.Lifetime.ApplicationStopping);
}

app.Run();

static IEnumerable<string> SplitList(string value)
    => value.Split(new[] { ',', ';', '\n', '\r', '\t' },
        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

// Ephemeral self-signed certificate (no files are created or required)
static class EphemeralCert
{
    public static X509Certificate2 Create()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=auth-host",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("auth-host");
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var now = DateTimeOffset.UtcNow.AddMinutes(-5);
        var cert = req.CreateSelfSigned(now, now.AddYears(5));
        // Rewrap to ensure Kestrel can access the private key across platforms
        return new X509Certificate2(cert.Export(X509ContentType.Pfx));
    }
}
