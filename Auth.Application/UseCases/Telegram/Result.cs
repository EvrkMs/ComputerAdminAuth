namespace Auth.Application;

public record Result(bool Success, string? Error = null)
{
    public static Result Ok() => new(true);
    public static Result Fail(string error) => new(false, error);
}
