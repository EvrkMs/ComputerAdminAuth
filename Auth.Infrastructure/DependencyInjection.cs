using Auth.Application.Interfaces;
using Auth.Application.UseCases.Users;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Auth.EntityFramework.Repositories;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Shared.Contracts;
using Auth.TelegramAuth.Interface;
using Auth.TelegramAuth.Options;
using Auth.TelegramAuth.Service;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Auth.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        AddTelegramAuth(services, config);
        AddPersistence(services, config);
        AddIdentity(services);
        ConfigureApplicationCookies(services, config);
        ConfigureAuthorizationPolicies(services);
        AddOpenIddictServer(services, config);

        services.AddScoped<ITelegramRepository, TelegramRepository>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IUserAdministrationService, UserAdministrationService>();
        services.AddMemoryCache();
        services.AddSingleton<IPasswordConfirmationService, PasswordConfirmationService>();

        return services;
    }

    private static void AddTelegramAuth(IServiceCollection services, IConfiguration config)
    {
        services.Configure<TelegramAuthOptions>(config.GetSection("Telegram"));

        services.AddSingleton<ITelegramAuthService>(sp =>
        {
            var opt = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<TelegramAuthOptions>>().Value;
            return new TelegramAuthService(opt);
        });
    }

    private static void AddPersistence(IServiceCollection services, IConfiguration config)
    {
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<ISessionRepository, SessionRepository>();
        services.AddScoped<ISessionService, SessionService>();
        services.AddHostedService<RevokedSessionCleanupService>();

        services.AddDbContext<AppDbContext>(options =>
        {
            var cs = ResolveConnectionString(config);

            options.UseNpgsql(cs, npgsql =>
            {
                npgsql.EnableRetryOnFailure(5, TimeSpan.FromSeconds(3), null);
                npgsql.CommandTimeout(15);
            });
        });
    }

    private static string ResolveConnectionString(IConfiguration config)
    {
        var cs = config.GetConnectionString("DefaultConnection");
        if (string.IsNullOrEmpty(cs))
            cs = config["CONNECTIONSTRINGS__DEFAULTCONNECTION"];

        return string.IsNullOrEmpty(cs)
            ? throw new InvalidOperationException("Database connection string not found in configuration or environment.")
            : cs;
    }

    private static void AddIdentity(IServiceCollection services)
    {
        services.AddIdentity<UserEntity, IdentityRole<Guid>>(options =>
        {
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = false;
            options.SignIn.RequireConfirmedEmail = false;
            options.SignIn.RequireConfirmedPhoneNumber = false;
            options.User.RequireUniqueEmail = false;

            options.ClaimsIdentity.UserIdClaimType = System.Security.Claims.ClaimTypes.NameIdentifier;
            options.ClaimsIdentity.UserNameClaimType = System.Security.Claims.ClaimTypes.Name;
            options.ClaimsIdentity.RoleClaimType = System.Security.Claims.ClaimTypes.Role;
        })
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();

        services.AddScoped<CustomSignInManager>();
        services.AddScoped<SignInManager<UserEntity>>(sp => sp.GetRequiredService<CustomSignInManager>());
    }

    private static void ConfigureApplicationCookies(IServiceCollection services, IConfiguration config)
    {
        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/Account/Login";
            options.LogoutPath = "/Account/Logout";
            options.Cookie.Name = "AuthCookie";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.ExpireTimeSpan = TimeSpan.FromDays(30);
            options.SlidingExpiration = true;
        });

        var dpKeysDir = config["DataProtection:KeysDirectory"] ?? "/keys/dataprotection";
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(dpKeysDir))
            .SetApplicationName("auth-host")
            .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
    }

    private static void ConfigureAuthorizationPolicies(IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy("Api", p => p.RequireAssertion(ctx => ctx.User.HasScope(ApiScopes.Api)))
            .AddPolicy("ApiRead", p => p.RequireAssertion(ctx =>
                ctx.User.HasScope(ApiScopes.Api) || ctx.User.HasScope(ApiScopes.ApiRead)))
            .AddPolicy("ApiWrite", p => p.RequireAssertion(ctx =>
                ctx.User.HasScope(ApiScopes.ApiWrite) || ctx.User.HasScope(ApiScopes.Api)));
    }

    private static void AddOpenIddictServer(IServiceCollection services, IConfiguration config)
    {
        services.AddOpenIddict()
            .AddCore(opt =>
            {
                opt.UseEntityFrameworkCore().UseDbContext<AppDbContext>();
            })
            .AddServer(opt =>
            {
                ConfigureOpenIddictServer(opt, config);
            })
            .AddValidation(opt =>
            {
                opt.UseLocalServer();
                opt.UseAspNetCore();
                opt.AddAudiences("computerclub_api");
            });
    }

    private static void ConfigureOpenIddictServer(OpenIddictServerBuilder opt, IConfiguration config)
    {
        opt.SetIssuer("https://auth.ava-kk.ru");

        opt.SetAuthorizationEndpointUris("/connect/authorize")
           .SetTokenEndpointUris("/connect/token")
           .SetUserInfoEndpointUris("/connect/userinfo")
           .SetIntrospectionEndpointUris("/connect/introspect")
           .SetRevocationEndpointUris("/connect/revocation")
           .SetEndSessionEndpointUris("/connect/logout");

        opt.AllowClientCredentialsFlow();

        opt.AllowAuthorizationCodeFlow()
           .RequireProofKeyForCodeExchange()
           .AllowRefreshTokenFlow();

        opt.RegisterScopes("openid", "profile",
            ApiScopes.Api, ApiScopes.ApiRead, ApiScopes.ApiWrite, "offline_access");

        opt.RegisterClaims("sid");

        opt.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        ConfigureSigningCertificates(opt, config);

        opt.AddDevelopmentEncryptionCertificate();
        opt.DisableAccessTokenEncryption();
        opt.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));
        opt.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
        opt.UseReferenceAccessTokens();
    }

    private static void ConfigureSigningCertificates(OpenIddictServerBuilder opt, IConfiguration config)
    {
        var signingPath = config["OpenIddict:SigningCertificate:Path"]
                           ?? Environment.GetEnvironmentVariable("OIDC_SIGNING_CERTIFICATE_PATH")
                           ?? "/keys/openiddict/signing.pfx";
        var signingPwd = config["OpenIddict:SigningCertificate:Password"]
                          ?? Environment.GetEnvironmentVariable("OIDC_SIGNING_CERTIFICATE_PASSWORD");

        try
        {
            var dir = Path.GetDirectoryName(signingPath);
            if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            if (!File.Exists(signingPath) && !string.IsNullOrWhiteSpace(signingPwd))
            {
                using var rsa = RSA.Create(2048);
                var req = new CertificateRequest(
                    new X500DistinguishedName("CN=auth-openiddict"),
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

                var now = DateTimeOffset.UtcNow.AddMinutes(-5);
                using var certGen = req.CreateSelfSigned(now, now.AddYears(5));
                var pfxBytes = certGen.Export(X509ContentType.Pfx, signingPwd);
                File.WriteAllBytes(signingPath, pfxBytes);
            }

            if (File.Exists(signingPath) && !string.IsNullOrWhiteSpace(signingPwd))
            {
                var cert = X509CertificateLoader.LoadPkcs12FromFile(signingPath, signingPwd, X509KeyStorageFlags.MachineKeySet);
                opt.AddSigningCertificate(cert);
            }
            else
            {
                opt.AddDevelopmentSigningCertificate();
            }
        }
        catch
        {
            opt.AddDevelopmentSigningCertificate();
        }
    }
}
