using System.Collections.ObjectModel;

namespace Auth.Application;

public record OperationResult(bool Success, string? Error = null, IReadOnlyDictionary<string, string[]>? ValidationErrors = null)
{
    public static OperationResult Ok() => new(true);

    public static OperationResult Fail(string error)
        => new(false, error);

    public static OperationResult Validation(IDictionary<string, string[]> errors)
        => new(false, null, new ReadOnlyDictionary<string, string[]>(errors));
}

public sealed record OperationResult<T>(bool Success, T? Value, string? Error = null, IReadOnlyDictionary<string, string[]>? ValidationErrors = null)
    : OperationResult(Success, Error, ValidationErrors)
{
    public static OperationResult<T> Ok(T value)
        => new(true, value);

    public static new OperationResult<T> Fail(string error)
        => new(false, default, error);

    public static new OperationResult<T> Validation(IDictionary<string, string[]> errors)
        => new(false, default, null, new ReadOnlyDictionary<string, string[]>(errors));
}
