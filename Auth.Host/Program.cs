using Auth.Application.UseCases;
using Auth.Host.Middleware;
using Auth.Host.ProfileService;
using Auth.Host.Services.Cors;
using Auth.Infrastructure;
using Auth.Infrastructure.Seeder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
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
// Application + Infrastructure
services.AddApplication();
services.AddInfrastructure(cfg);

// Razor Pages + API controllers
services.AddRazorPages();
services.AddControllers()
    .AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: true));
        o.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

// Response compression (Brotli/Gzip) for HTML/JSON
services.AddResponseCompression(o =>
{
    o.EnableForHttps = true;
    o.Providers.Add<BrotliCompressionProvider>();
    o.Providers.Add<GzipCompressionProvider>();
    o.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[]
    {
        "application/json",
        "application/problem+json"
    });
});
services.Configure<BrotliCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);
services.Configure<GzipCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);

// Output caching: cache anonymous GETs for short time
services.AddOutputCache(o =>
{
    o.AddPolicy("AnonRazor", b => b
        .Expire(TimeSpan.FromSeconds(60))
        .SetVaryByQuery("*")
        .SetVaryByHeader("Accept-Encoding")
        .SetVaryByHeader("Cookie"));
});

services.AddScoped<IOpenIddictProfileService, OpenIddictProfileService>();
services.AddScoped<Auth.Host.Services.SessionCookieGuard>();
services.AddScoped<Auth.Host.Services.SessionCookieBinder>();
services.AddScoped<Auth.Host.Services.SessionBindingService>();
services.AddScoped<Auth.Host.Services.Authorization.AuthorizationInteractionService>();

services.AddAvaCors();

// Smart authentication scheme: OpenIddict validation for API, Cookies otherwise
services.AddAuthentication(options =>
{
    options.DefaultScheme = "smart";
})
.AddPolicyScheme("smart", "Dynamic scheme", options =>
{
    options.ForwardDefaultSelector = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api"))
            return OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

        if (ctx.Request.Headers.ContainsKey("Authorization"))
            return OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

        return IdentityConstants.ApplicationScheme;
    };
});

// Antiforgery / HSTS handled at reverse proxy; set antiforgery header name here
services.AddAntiforgery(o =>
{
    o.HeaderName = "X-CSRF-TOKEN";
});

// Basic rate limiting: stricter limits for token endpoints
services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

var app = builder.Build();

app.UseMiddleware<CloudflareTrueClientIpMiddleware>();

var forwardedConfig = Environment.GetEnvironmentVariable("TRUSTED_FORWARDERS");
var forwardedOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
    RequireHeaderSymmetry = false,
    ForwardLimit = null
};
forwardedOptions.KnownNetworks.Clear();
forwardedOptions.KnownProxies.Clear();

var unresolvedForwarders = new List<string>();
if (!string.IsNullOrWhiteSpace(forwardedConfig))
{
    foreach (var entry in forwardedConfig.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (IPAddress.TryParse(entry, out var ip))
        {
            forwardedOptions.KnownProxies.Add(ip);
            continue;
        }

        try
        {
            var addresses = Dns.GetHostAddresses(entry);
            if (addresses.Length == 0)
            {
                unresolvedForwarders.Add(entry);
                continue;
            }

            foreach (var address in addresses)
            {
                if (address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                {
                    forwardedOptions.KnownProxies.Add(address);
                }
            }
        }
        catch (Exception ex)
        {
            unresolvedForwarders.Add(entry + $" ({ex.Message})");
        }
    }
}

app.UseForwardedHeaders(forwardedOptions);
if (unresolvedForwarders.Count > 0)
{
    app.Logger.LogWarning("Failed to resolve some TRUSTED_FORWARDERS entries: {Entries}", string.Join(", ", unresolvedForwarders));
}

app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.None,
    Secure = CookieSecurePolicy.Always
});

// Pipeline
// Avoid response compression for OpenID Connect endpoints to prevent
// any proxy/client inconsistencies with Content-Length/body size during token exchange.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/connect"))
    {
        // Remove accepted encodings so ResponseCompression won't engage.
        context.Request.Headers.Remove("Accept-Encoding");
    }
    await next();
});

app.UseResponseCompression();
app.UseRouting();
// CORS logging middleware (place before UseCors to capture preflight short-circuit)
app.Use(async (context, next) =>
{
    var origin = context.Request.Headers["Origin"].ToString();
    if (!string.IsNullOrEmpty(origin))
    {
        var preflightMethod = context.Request.Headers["Access-Control-Request-Method"].ToString();
        var preflightHeaders = context.Request.Headers["Access-Control-Request-Headers"].ToString();

        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("CorsLogger")
            .LogInformation(
                "CORS request {Method} {Path} Origin={Origin} ACRM={ACRM} ACRH={ACRH}",
                context.Request.Method,
                context.Request.Path,
                origin,
                preflightMethod,
                preflightHeaders);

        context.Response.OnStarting(state =>
        {
            var http = (HttpContext)state;
            var aco = http.Response.Headers["Access-Control-Allow-Origin"].ToString();
            var acm = http.Response.Headers["Access-Control-Allow-Methods"].ToString();
            var ach = http.Response.Headers["Access-Control-Allow-Headers"].ToString();
            var acc = http.Response.Headers["Access-Control-Allow-Credentials"].ToString();

            http.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("CorsLogger")
                .LogInformation(
                    "CORS response {Status} ACO={ACO} ACM={ACM} ACH={ACH} ACC={ACC}",
                    http.Response.StatusCode, aco, acm, ach, acc);
            return Task.CompletedTask;
        }, context);
    }

    await next();
});
app.UseOutputCache();
// Apply global rate limiter with per-path budgets (tighter for /connect/*)
app.UseRateLimiter(new RateLimiterOptions
{
    GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var isConnect = context.Request.Path.StartsWithSegments("/connect");
        var key = (isConnect ? "connect:" : "other:") + ip;
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = isConnect ? 10 : 100,
            Window = TimeSpan.FromSeconds(10),
            QueueLimit = 0,
            AutoReplenishment = true
        });
    }),
    RejectionStatusCode = StatusCodes.Status429TooManyRequests
});
// OAuth/OIDC endpoints must not be cached: set headers before response starts
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/connect"))
    {
        context.Response.OnStarting(() =>
        {
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-cache";
            return Task.CompletedTask;
        });
    }
    await next();
});
app.UseCors(CorsPolicies.Ava);
app.UseAuthentication();
// Reject API calls if the DB session (sid) is revoked
app.UseSessionRevocationValidation();
app.UseAuthorization();

// Log slow requests to spot intermittent stalls
app.Use(async (context, next) =>
{
    var sw = Stopwatch.StartNew();
    try
    {
        await next();
    }
    finally
    {
        sw.Stop();
        if (sw.ElapsedMilliseconds > 1000)
        {
            app.Logger.LogWarning("Slow request {Method} {Path} took {Elapsed} ms, status {Status}",
                context.Request.Method, context.Request.Path, sw.ElapsedMilliseconds, context.Response.StatusCode);
        }
    }
});

// Endpoints
app.MapControllers();
app.MapRazorPages();
app.MapGet("/healthz", () => Results.Ok("ok"));

// Migrations + Seed
using (var scope = app.Services.CreateScope())
{
    var sp = scope.ServiceProvider;
    await sp.ApplyMigrationsAndSeedAsync(app.Lifetime.ApplicationStopping);
}

app.Run();

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
