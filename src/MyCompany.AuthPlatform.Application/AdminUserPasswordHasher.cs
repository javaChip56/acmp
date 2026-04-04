using System.Security.Cryptography;

namespace MyCompany.AuthPlatform.Application;

public static class AdminUserPasswordHasher
{
    public const string Algorithm = "PBKDF2-SHA256";
    public const int DefaultIterations = 100_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static (byte[] Hash, byte[] Salt, int Iterations) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            DefaultIterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return (hash, salt, DefaultIterations);
    }

    public static bool VerifyPassword(
        string password,
        byte[] expectedHash,
        byte[] salt,
        int iterations,
        string algorithm)
    {
        if (!string.Equals(algorithm, Algorithm, StringComparison.Ordinal))
        {
            return false;
        }

        var computedHash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expectedHash.Length);

        return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
    }
}
