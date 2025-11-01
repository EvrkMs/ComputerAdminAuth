using Auth.TelegramAuth.Interface;
using Auth.TelegramAuth.Options;
using Auth.TelegramAuth.Service;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.TelegramAuth;


public static class DependencyInjection
{
    public static IServiceCollection AddTelegramAuth(this IServiceCollection services, Action<TelegramAuthOptions> configure)
    {
        var opts = new TelegramAuthOptions { BotToken = "" };
        configure(opts);
        services.AddSingleton(opts);
        services.AddScoped<ITelegramAuthService, TelegramAuthService>();
        return services;
    }
}
