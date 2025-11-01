// Namespace: Auth.TelegramAuth (библиотека)
using Auth.TelegramAuth.Raw;

namespace Auth.TelegramAuth.Interface;

public interface ITelegramAuthService
{
    bool VerifyWidget(TelegramRawData dto, out string? error);
}
