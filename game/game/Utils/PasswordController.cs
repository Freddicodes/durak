using System.Security.Cryptography;

namespace game.Utils;

public class PasswordController
{
    /// <summary>
    /// Provides the capability to hash passwords and verify existing hashes against passwords.
    /// </summary>
    private const int SaltLength = 16;

    private const int HashLength = 20;
    private const int Iterations = 10000;
    private const string Prepend = "HASH#";


    /// <summary>
    /// Creates A Hash for the given Password
    /// </summary>
    /// <param name="pw">The user password</param>
    /// <returns>A hashed password</returns>
    /// <exception cref="ArgumentException">When pw is null</exception>
    public static string Hash(string pw)
    {
        if (pw == null) throw new ArgumentException("Password must not be null.");
        // generate salt value
        byte[] salt = new byte[SaltLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        // hash pw with salt
        var result = new Rfc2898DeriveBytes(pw, salt, Iterations, HashAlgorithmName.SHA512);
        var hash = result.GetBytes(HashLength);
        // combine salt and has to final product
        var combined = new byte[HashLength + SaltLength];
        Array.Copy(salt, 0, combined, 0, SaltLength);
        Array.Copy(hash, 0, combined, SaltLength, HashLength);
        var base64 = Convert.ToBase64String(combined);
        return Prepend + base64;
    }

    private static bool IsSupported(string hashStr)
    {
        return hashStr.Contains(Prepend);
    }

    /// <summary>
    /// A method to verify a password hash for a given password.
    /// </summary>
    /// <param name="pw">The user password</param>
    /// <param name="hash">The hash that is compared</param>
    /// <returns>True or false depending on equality of the inputs</returns>
    /// <exception cref="NotSupportedException">If the hash has the wrong format</exception>
    public static bool Verify(string pw, string hash) 
    {
        // check format
        if (!IsSupported(hash)) throw new NotSupportedException("String must have proper format.");
        // remove tag
        var cleanHash = hash.Replace(Prepend, "");
        // retrieve hash
        var hashBytes = Convert.FromBase64String(cleanHash);
        var saltByte = new byte[SaltLength];
        var noSalt = new byte[HashLength];
        // get salt and hash
        Array.Copy(hashBytes, 0, saltByte, 0, SaltLength);
        Array.Copy(hashBytes, SaltLength, noSalt, 0, HashLength);
        // create new hash and compare
        var result = new Rfc2898DeriveBytes(pw, saltByte, Iterations, HashAlgorithmName.SHA512);
        byte[] final = result.GetBytes(HashLength);
        return final.SequenceEqual(noSalt);
    }
}
