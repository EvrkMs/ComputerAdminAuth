using System;
using System.Linq;
using System.Net;
using Auth.TokenValidation.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Auth.TokenValidation;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthTokenIntrospection(
        this IServiceCollection services,
        Action<AuthIntrospectionOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.AddOptions<AuthIntrospectionOptions>()
            .Configure(configureOptions)
            .ValidateDataAnnotations();

        RegisterHttpClient(services);
        return services;
    }

    public static IServiceCollection AddAuthTokenIntrospection(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "Auth:Introspection")
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<AuthIntrospectionOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations();

        RegisterHttpClient(services);
        return services;
    }

    public static IServiceCollection AddAuthTokenIntrospection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AuthIntrospectionOptions>();
        RegisterHttpClient(services);
        return services;
    }

    private static void RegisterHttpClient(IServiceCollection services)
    {
        if (services.Any(sd => sd.ServiceType == typeof(ITokenIntrospector)))
        {
            return;
        }

        services.AddHttpClient<ITokenIntrospector, TokenIntrospector>(static (sp, client) =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestVersion = HttpVersion.Version20;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
        })
        .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.All
        });
    }
}
