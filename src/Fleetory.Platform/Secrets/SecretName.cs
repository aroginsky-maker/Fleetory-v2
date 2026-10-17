namespace Fleetory.Platform.Secrets;

internal static class SecretName
{
    public static void Validate(string? name)
    {
        if (string.IsNullOrEmpty(name) ||
            name.Length > 128 ||
            name is "." or ".." ||
            name.Any(character =>
                character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.')))
        {
            throw new ArgumentException("Secret name is invalid.", nameof(name));
        }
    }
}
