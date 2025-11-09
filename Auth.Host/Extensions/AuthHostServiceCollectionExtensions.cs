using Auth.Application.UseCases;
using Auth.Host.ProfileService;
using Auth.Host.Services.Authorization;
using Auth.Host.Services.Authorization.Handlers;
using Auth.Host.Services.Cors;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO.Compression;
using System.Text.Json.Serialization;

namespace Auth.Host.Extensions;

internal static class AuthHostServiceCollectionExtensions
{
    /// <summary>
    /// Registers application/infrastructure services and presentation layer features.
    /// Definitions live here to keep Program.cs lean.
    /// </summary>
    public static IServiceCollection AddAuthHostServices(this IServiceCollection services, IConfiguration cfg)
    {
        // Application + data access
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
        services.AddScoped<SessionCookieWorkflow>();
        services.AddScoped<Auth.Host.Services.SessionCookieGuard>();
        services.AddScoped<Auth.Host.Services.SessionCookieBinder>();
        services.AddScoped<Auth.Host.Services.SessionBindingService>();
        services.AddScoped<AuthorizeRequestHandler>();
        services.AddScoped<TokenExchangeHandler>();
        services.AddScoped<UserInfoRequestHandler>();
        services.AddScoped<LogoutRequestHandler>();
        services.AddScoped<AuthorizationInteractionService>();

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
                    return OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

                if (ctx.Request.Headers.ContainsKey("Authorization"))
                    return OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

                return IdentityConstants.ApplicationScheme;
            };
        });

        // Antiforgery / HSTS handled at reverse proxy; set antiforgery header name here
        services.AddAntiforgery(o =>
        {
            o.HeaderName = "X-CSRF-TOKEN";
        });

        // Basic rate limiting: stricter limits for token endpoints (policy set in pipeline)
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });

        return services;
    }
}
