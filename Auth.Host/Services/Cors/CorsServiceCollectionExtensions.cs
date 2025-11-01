using Microsoft.Extensions.DependencyInjection;

namespace Auth.Host.Services.Cors;

public static class CorsServiceCollectionExtensions
{
    public static IServiceCollection AddAvaCors(this IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy(CorsPolicies.Ava, builder =>
            {
                builder.SetIsOriginAllowed(origin =>
                    IsAllowedAvaOrigin(origin))
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
        });

        return services;
    }

    private static bool IsAllowedAvaOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            return false;

        // allow https and http (for staging/dev tunnels)
        if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) &&
            !uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var host = uri.Host.TrimEnd('.');
        if (host.Equals("ava-kk.ru", StringComparison.OrdinalIgnoreCase))
            return true;

        return host.EndsWith(".ava-kk.ru", StringComparison.OrdinalIgnoreCase);
    }
}
