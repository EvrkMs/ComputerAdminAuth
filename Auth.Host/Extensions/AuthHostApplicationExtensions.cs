using Auth.Host.Middleware;
using Auth.Host.Options;
using Auth.Host.Services.Cors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;
using System.Threading.Tasks;

namespace Auth.Host.Extensions;

internal static class AuthHostApplicationExtensions
{
    /// <summary>
    /// Composes the request pipeline. Keeping this here avoids a 200+ line Program.cs block.
    /// </summary>
    public static WebApplication UseAuthHostPipeline(this WebApplication app, IConfiguration cfg)
    {
        var cloudflareOptions = app.Services.GetRequiredService<IOptions<CloudflareOptions>>().Value;
        if (cloudflareOptions.Enabled)
        {
            app.UseMiddleware<CloudflareTrueClientIpMiddleware>();
        }

        ConfigureForwarders(app, cfg);

        app.UseCookiePolicy(new CookiePolicyOptions
        {
            MinimumSameSitePolicy = SameSiteMode.None,
            Secure = CookieSecurePolicy.Always
        });

        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/connect"))
            {
                context.Request.Headers.Remove("Accept-Encoding");
            }
            await next();
        });

        app.UseResponseCompression();
        app.UseRouting();

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
        app.UseAuthorization();

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

        app.MapControllers();
        app.MapRazorPages();
        app.MapGet("/healthz", () => Results.Ok("ok"));

        return app;
    }

    private static void ConfigureForwarders(WebApplication app, IConfiguration cfg)
    {
        var forwardedConfig = cfg["TRUSTED_FORWARDERS"] ?? Environment.GetEnvironmentVariable("TRUSTED_FORWARDERS");
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
    }
}
