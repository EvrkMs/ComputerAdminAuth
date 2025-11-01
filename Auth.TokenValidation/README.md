# Auth.TokenValidation

Библиотека для обращения к `auth.service` через стандартную точку `/connect/introspect` и проверки опаковых access-токенов, которые выдаёт OpenIddict.

## Подключение

1. Добавьте ссылку на проект/пакет `Auth.TokenValidation`.
2. Зарегистрируйте клиент с правом `introspection` (в сидере уже есть `svc.introspector`).
3. Проставьте в `appsettings` секцию, например:

```json
"Auth": {
  "Introspection": {
    "Authority": "https://auth.ava-kk.ru",
    "ClientId": "svc.introspector",
    "ClientSecret": "super-secret",
    "TokenTypeHint": "access_token"
  }
}
```

4. Подключите DI-расширение:

```csharp
builder.Services.AddAuthTokenIntrospection(builder.Configuration);
// или
builder.Services.AddAuthTokenIntrospection(options =>
{
    options.Authority = "https://auth.ava-kk.ru";
    options.ClientId = "svc.introspector";
    options.ClientSecret = Environment.GetEnvironmentVariable("OIDC_SVC_INTROSPECTOR_SECRET")!;
});
```

После этого `ITokenIntrospector` доступен через DI.

## Использование

```csharp
public class SampleMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITokenIntrospector _introspector;

    public SampleMiddleware(RequestDelegate next, ITokenIntrospector introspector)
    {
        _next = next;
        _introspector = introspector;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var raw))
        {
            await _next(context);
            return;
        }

        var token = raw.ToString()["Bearer ".Length..];
        var result = await _introspector.IntrospectAsync(token, context.RequestAborted);
        if (!result.Active)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Тут можно построить ClaimsPrincipal из result.Raw или просто проверить нужные scope'ы
        await _next(context);
    }
}
```

`TokenIntrospectionResult` содержит:

- `Active` — признак валидности токена;
- `Scopes`/`Audiences`/`Subject`/`ClientId` и метаданные по времени жизни;
- `Raw` — словарь с дополнительными клеймами (`sid`, `role`, `email` и т. д.).
