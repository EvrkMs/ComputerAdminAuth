using Auth.Application.UseCases.Telegram;
using Auth.Application.UseCases.Users;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Application.UseCases;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<GetMyTelegramQuery>();
        services.AddTransient<UnbindTelegramCommand>();
        services.AddScoped<BindTelegramCommand>();

        return services;
    }
}
