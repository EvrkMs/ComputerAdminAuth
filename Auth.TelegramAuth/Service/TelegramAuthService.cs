// Namespace: Auth.TelegramAuth (библиотека)
using Auth.TelegramAuth.Interface;
using Auth.TelegramAuth.Options;
using Auth.TelegramAuth.Raw;
using System.Security.Cryptography;
using System.Text;

namespace Auth.TelegramAuth.Service;

public sealed class TelegramAuthService : ITelegramAuthService
{
    private readonly TelegramAuthOptions _opt;
    public TelegramAuthService(TelegramAuthOptions opt)
    {
        _opt = opt ?? throw new ArgumentNullException(nameof(opt));
        if (string.IsNullOrWhiteSpace(_opt.BotToken))
            throw new ArgumentException("BotToken is required", nameof(opt));
    }

    // ===== Login Widget =====
    public bool VerifyWidget(TelegramRawData dto, out string? error)
    {
        error = null;
        if (dto.Id <= 0 || dto.AuthDate <= 0 || string.IsNullOrWhiteSpace(dto.Hash))
        {
            error = "missing_fields"; return false;
        }

        if (!CheckTtl(dto.AuthDate, _opt.AllowedClockSkewSeconds))
        {
            error = "stale_request"; return false;
        }

        var dataCheck = BuildDataCheckString(new Dictionary<string, string?>
        {
            ["auth_date"] = dto.AuthDate.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["first_name"] = dto.FirstName,
            ["id"] = dto.Id.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["last_name"] = dto.LastName,
            ["photo_url"] = dto.PhotoUrl,
            ["username"] = dto.Username
        });

        // secret = SHA256(bot_token)
        var secret = SHA256.HashData(Encoding.UTF8.GetBytes(_opt.BotToken));
        var calc = HmacHex(secret, dataCheck);

        return ConstantTimeEquals(calc, dto.Hash);
    }

    // ===== WebApp initData =====
    // ===== Helpers =====
    private static bool CheckTtl(long authUnix, int skewSeconds)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return Math.Abs(now - authUnix) <= Math.Max(30, skewSeconds);
    }

    private static string BuildDataCheckString(IDictionary<string, string?> dict) =>
        string.Join('\n',
            dict.Where(kv => !string.IsNullOrEmpty(kv.Value))
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => $"{kv.Key}={kv.Value}")
        );

    private static string HmacHex(byte[] key, string message)
    {
        using var h = new HMACSHA256(key);
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(message))).ToLowerInvariant();
    }

    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
