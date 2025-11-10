## ComputerAdminAuth

ASP.NET Core/OpenIddict host that issues tokens for ComputerAdmin services. The solution targets **.NET 9.0** and uses **PostgreSQL 18** (tested with 18.x). Make sure these toolchains are available locally before running migrations/tests.

### Environment variables

Configuration is typically provided via `.env` files (see `auth-host.env.sample`) or the host environment. Important settings:

| Variable | Description |
| --- | --- |
| `CONNECTIONSTRINGS__DEFAULTCONNECTION` | PostgreSQL connection string (Npgsql format). |
| `TRUSTED_FORWARDERS` | Proxies whose forwarding headers are honored (comma/semicolon separated host/IP list). |
| `USE_CLOUDFLARE` | `true/false`. Enables Cloudflare header normalization middleware. Can also be set via `Cloudflare:Enabled` in configuration. |
| `CLOUDFLARE_TRUSTED_PROXIES` | List of Cloudflare egress IPs/CIDR ranges (comma/semicolon separated). Only requests originating from these networks have Cloudflare headers applied. |
| `CLOUDFLARE_ALLOW_TRUE_CLIENT_IP` | Enables parsing of the `True-Client-IP` header (only turn on when your CDN actually sends it). |
| `SESSION_COOKIE_DOMAIN` / `SESSION_COOKIE_PATH` | Controls which domain/path can read the `sid` cookie (defaults to `.ava-kk.ru` and `/`). |
| `SESSION_COOKIE_SAMESITE` / `SESSION_COOKIE_SECURE` | Fine-tunes cookie behavior (`None` + `true` recommended for cross-site HTTPS-only flows). |
| `REDIS__CONNECTIONSTRING` | Redis endpoint used to publish token/session revocation notifications (e.g. `redis:6379`). |
| `REDIS__REVOCATIONCHANNEL` | Pub/Sub channel name for revoked token notifications (defaults to `revoked_tokens`). |
| `TELEGRAM__BOTTOKEN` | Telegram bot token for widget verification. |
| `TELEGRAM__ALLOWEDCLOCKSKEWSECONDS` | Widget timestamp skew allowance (defaults to 300 seconds if omitted). |
| `OIDC_SIGNING_CERTIFICATE_PATH/PASSWORD` | Path/password for the OpenIddict signing certificate (auto-generated when both are provided). |
| `DATAPROTECTION__KEYSDIRECTORY` | Directory for ASP.NET Data Protection keys. |
| `ASPNETCORE_URLS` / `ASPNETCORE_HTTP_PORTS` | Listeners exposed by Auth.Host (defaults bind HTTPS 5001). |

Copy `auth-host.env.sample` to `.env` (or the location your orchestrator expects) and fill in the secrets before running `dotnet run --project Auth.Host`.

### Database migrations

Migrations live in `Auth.EntityFramework`. Ensure your PostgreSQL 18 instance is reachable, then apply migrations with:

```bash
dotnet ef database update --project Auth.EntityFramework --startup-project Auth.Host
```

The host automatically runs the same step during startup via `ApplyMigrationsAndSeedAsync`.
