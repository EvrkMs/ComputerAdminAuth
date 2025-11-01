using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Infrastructure.Seeder;

public static class OpenIddictSeeder
{
    public static async Task SeedAsync(IServiceProvider sp)
    {
        using var scope = sp.CreateScope();
        var scopeMgr = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var appMgr = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // === Scopes ===
        await EnsureScopeAsync(scopeMgr, "openid", "OpenID Connect");
        await EnsureScopeAsync(scopeMgr, "profile", "Profile");
        await EnsureScopeAsync(scopeMgr, "telegram", "Telegram profile");

        // Твои API scopes, привязанные к ресурсу (аудитории) "computerclub_api"
        await EnsureScopeAsync(scopeMgr, "api", "Full access to Computer Club API", ["computerclub_api"]);
        await EnsureScopeAsync(scopeMgr, "api:read", "Read-only access", ["computerclub_api"]);
        await EnsureScopeAsync(scopeMgr, "api:write", "Write access", ["computerclub_api"]);

        // Новые scope'ы для machine-to-machine сценариев (пример)
        await EnsureScopeAsync(scopeMgr, "users.read", "Read users list", ["computerclub_api"]);
        // при необходимости:
        // await EnsureScopeAsync(scopeMgr, "users.write", "Modify users",                ["computerclub_api"]);

        // === Public SPA (react-spa) ===
        await EnsureOrUpdateSpaAsync(appMgr);

        // === Confidential: Client Credentials ===
        // Секреты — только из ENV/Secret Manager
        var reportingSecret = Environment.GetEnvironmentVariable("OIDC_SVC_REPORTING_SECRET");
        var introspectorSecret = Environment.GetEnvironmentVariable("OIDC_SVC_INTROSPECTOR_SECRET");

        await EnsureOrUpdateClientCredentialsAsync(
            appMgr,
            clientId: "svc.reporting",
            displayName: "Reporting Service",
            scopes: new[] { "users.read" }, // какие scope'ы разрешаем этому сервису
            clientSecret: reportingSecret    // может быть null при update без ротации
        );

        // === Confidential: Introspection client (для /connect/introspect) ===
        await EnsureOrUpdateIntrospectorAsync(
            appMgr,
            clientId: "svc.introspector",
            displayName: "Token Introspector",
            clientSecret: introspectorSecret
        );

        await EnsureOrUpdateResourceServerAsync(
            appMgr,
            clientId: "computerclub_api",
            displayName: "Computer Club API (Resource Server)",
            clientSecret: Environment.GetEnvironmentVariable("OIDC_RESOURCE_SECRET")
        );
    }

    // ---------- Helpers ----------

    private static async Task EnsureScopeAsync(
        IOpenIddictScopeManager scopeMgr,
        string name,
        string? displayName = null,
        string[]? resources = null)
    {
        var handle = await scopeMgr.FindByNameAsync(name);
        if (handle is null)
        {
            var d = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = displayName ?? name
            };
            if (resources is { Length: > 0 })
                d.Resources.UnionWith(resources);

            await scopeMgr.CreateAsync(d);
            return;
        }

        // Обновление: берём текущее, перезаписываем ресурсы ровно на нужные
        var update = new OpenIddictScopeDescriptor
        {
            Name = name,
            DisplayName = displayName ?? name
        };
        update.Resources.UnionWith(resources ?? Array.Empty<string>());

        await scopeMgr.UpdateAsync(handle, update);
    }

    private static async Task EnsureOrUpdateSpaAsync(IOpenIddictApplicationManager appMgr)
    {
        const string clientId = "react-spa";
        var existing = await appMgr.FindByClientIdAsync(clientId);

        var desc = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = "React SPA",
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Explicit
        };

        desc.RedirectUris.Add(new Uri("https://admin.ava-kk.ru/callback"));
        desc.RedirectUris.Add(new Uri("https://admin.ava-kk.ru/silent-callback.html"));
        desc.PostLogoutRedirectUris.Add(new Uri("https://admin.ava-kk.ru/logout-callback"));
        desc.Permissions.UnionWith(
        [
            // endpoints
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.Revocation,
            Permissions.Endpoints.EndSession,

            // grant/response
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,

            // scopes
            Scopes.OpenId,
            Permissions.Scopes.Profile,
            Permissions.Prefixes.Scope + "telegram",
            Permissions.Prefixes.Scope + "api",
            Permissions.Prefixes.Scope + "api:read",
            Permissions.Prefixes.Scope + "api:write",
            Permissions.Prefixes.Scope + "offline_access"
        ]);

        // PKCE required для публичного клиента
        desc.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);

        if (existing is null)
            await appMgr.CreateAsync(desc);
        else
            await appMgr.UpdateAsync(existing, await MergeWithExistingAsync(appMgr, existing, desc));
    }

    private static async Task EnsureOrUpdateClientCredentialsAsync(
        IOpenIddictApplicationManager appMgr,
        string clientId,
        string displayName,
        string[] scopes,
        string? clientSecret)
    {
        var existing = await appMgr.FindByClientIdAsync(clientId);

        var desc = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit // нет человеческого согласия для M2M
        };

        desc.Permissions.UnionWith(
        [
            Permissions.Endpoints.Token,
            Permissions.GrantTypes.ClientCredentials
        ]);

        foreach (var s in scopes)
            desc.Permissions.Add(Permissions.Prefixes.Scope + s);

        // ВАЖНО: секрет задаём ТОЛЬКО если он есть (создание или ротация).
        if (!string.IsNullOrWhiteSpace(clientSecret))
            desc.ClientSecret = clientSecret;

        if (existing is null)
        {
            if (string.IsNullOrWhiteSpace(desc.ClientSecret))
                throw new InvalidOperationException($"Environment secret for {clientId} is not set.");
            await appMgr.CreateAsync(desc);
        }
        else
        {
            // Не стираем секрет при апдейте: мержим с текущей конфигурацией.
            var merged = await MergeWithExistingAsync(appMgr, existing, desc, keepExistingSecretIfMissing: true);
            await appMgr.UpdateAsync(existing, merged);
        }
    }
    private static async Task EnsureOrUpdateResourceServerAsync(
    IOpenIddictApplicationManager appMgr,
    string clientId,
    string displayName,
    string? clientSecret)
    {
        var existing = await appMgr.FindByClientIdAsync(clientId);

        var desc = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            Permissions =
        {
            Permissions.Endpoints.Introspection // это главное право для ресурса
        }
        };

        if (!string.IsNullOrWhiteSpace(clientSecret))
            desc.ClientSecret = clientSecret;

        if (existing is null)
        {
            if (string.IsNullOrWhiteSpace(desc.ClientSecret))
                throw new InvalidOperationException($"ENV OIDC_RESOURCE_SECRET не задан для {clientId}.");
            await appMgr.CreateAsync(desc);
        }
        else
        {
            var merged = new OpenIddictApplicationDescriptor();
            await appMgr.PopulateAsync(merged, existing);

            merged.DisplayName = desc.DisplayName ?? merged.DisplayName;
            merged.ClientType = desc.ClientType ?? merged.ClientType;
            merged.ConsentType = desc.ConsentType ?? merged.ConsentType;

            merged.Permissions.Clear();
            merged.Permissions.UnionWith(desc.Permissions);

            if (!string.IsNullOrWhiteSpace(desc.ClientSecret))
                merged.ClientSecret = desc.ClientSecret;

            await appMgr.UpdateAsync(existing, merged);
        }
    }
    private static async Task EnsureOrUpdateIntrospectorAsync(
        IOpenIddictApplicationManager appMgr,
        string clientId,
        string displayName,
        string? clientSecret)
    {
        var existing = await appMgr.FindByClientIdAsync(clientId);

        var desc = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            Permissions =
            {
                Permissions.Endpoints.Introspection
            }
        };

        if (!string.IsNullOrWhiteSpace(clientSecret))
            desc.ClientSecret = clientSecret;

        if (existing is null)
        {
            if (string.IsNullOrWhiteSpace(desc.ClientSecret))
                throw new InvalidOperationException($"Environment secret for {clientId} is not set.");
            await appMgr.CreateAsync(desc);
        }
        else
        {
            var merged = await MergeWithExistingAsync(appMgr, existing, desc, keepExistingSecretIfMissing: true);
            await appMgr.UpdateAsync(existing, merged);
        }
    }

    /// <summary>
    /// Аккуратный merge: подтягиваем текущую конфигурацию, меняем только нужные поля.
    /// По умолчанию сохраняем старый секрет, если новый не задан.
    /// </summary>
    private static async Task<OpenIddictApplicationDescriptor> MergeWithExistingAsync(
        IOpenIddictApplicationManager appMgr,
        object handle,
        OpenIddictApplicationDescriptor desired,
        bool keepExistingSecretIfMissing = true)
    {
        var current = new OpenIddictApplicationDescriptor();
        await appMgr.PopulateAsync(current, handle);

        // Базовые поля
        current.DisplayName = desired.DisplayName ?? current.DisplayName;
        current.ClientType = desired.ClientType ?? current.ClientType;
        current.ConsentType = desired.ConsentType ?? current.ConsentType;

        // URIs (SPA/interactive)
        current.RedirectUris.Clear();
        current.RedirectUris.UnionWith(desired.RedirectUris);

        current.PostLogoutRedirectUris.Clear();
        current.PostLogoutRedirectUris.UnionWith(desired.PostLogoutRedirectUris);

        // Permissions/Requirements — перезаписываем на желаемые (явная конфигурация)
        current.Permissions.Clear();
        current.Permissions.UnionWith(desired.Permissions);

        current.Requirements.Clear();
        current.Requirements.UnionWith(desired.Requirements);

        // Секрет: задаём новый только если он предоставлен; иначе оставляем существующий
        if (!keepExistingSecretIfMissing || !string.IsNullOrWhiteSpace(desired.ClientSecret))
            current.ClientSecret = desired.ClientSecret;

        return current;
    }
}
