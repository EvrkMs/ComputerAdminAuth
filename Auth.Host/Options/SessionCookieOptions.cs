using Microsoft.AspNetCore.Http;

namespace Auth.Host.Options;

public sealed class SessionCookieOptions
{
    public string? Domain { get; set; } = ".ava-kk.ru";
    public string Path { get; set; } = "/";
    public SameSiteMode SameSite { get; set; } = SameSiteMode.None;
    public bool Secure { get; set; } = true;
}
