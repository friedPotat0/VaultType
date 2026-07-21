using System.Security.Cryptography;
using System.Text;

namespace VaultType.Vault.Crypto;

public enum KdfType { Pbkdf2Sha256 = 0, Argon2id = 1 }

// The parameters the server reports from /identity/accounts/prelogin. Never hardcode these -
// always use the values the server sends (iterations/memory/parallelism vary per account).
public sealed class KdfConfig
{
    public KdfType Type { get; init; } = KdfType.Pbkdf2Sha256;
    public int Iterations { get; init; } = 600_000;
    public int? MemoryMiB { get; init; }      // Argon2id only
    public int? Parallelism { get; init; }    // Argon2id only

    public static KdfConfig Pbkdf2(int iterations) => new() { Type = KdfType.Pbkdf2Sha256, Iterations = iterations };
    public static KdfConfig Argon2(int iterations, int memoryMiB, int parallelism)
        => new() { Type = KdfType.Argon2id, Iterations = iterations, MemoryMiB = memoryMiB, Parallelism = parallelism };
}

// Bitwarden's master-key derivation, master-password hash and key stretch. All output is raw
// key material; callers wipe it. Cross-checked against the Bitwarden security whitepaper and the
// BitwardenDecrypt / rbw / mvdan-bitw reference implementations.
public static class Kdf
{
    // The 32-byte master key from email + master password.
    //   PBKDF2: salt = raw lowercased-email bytes.
    //   Argon2id: salt = SHA-256 of the lowercased email (32 bytes) - the critical difference.
    public static byte[] DeriveMasterKey(string email, ReadOnlySpan<byte> password, KdfConfig kdf)
    {
        byte[] emailSalt = Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant());
        try
        {
            return kdf.Type == KdfType.Argon2id
                ? Argon2id(password, SHA256.HashData(emailSalt), kdf.Iterations,
                           (kdf.MemoryMiB ?? 64) * 1024, kdf.Parallelism ?? 4, 32)
                : Pbkdf2(password, emailSalt, kdf.Iterations, 32);
        }
        finally { CryptographicOperations.ZeroMemory(emailSalt); }
    }

    // The auth hash sent to the server as the token "password" field:
    //   base64( PBKDF2-SHA256(masterKey, salt=utf8(masterPassword), iterations=1, 32) ).
    public static string MasterPasswordAuthHash(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> password)
    {
        byte[] hash = Pbkdf2(masterKey, password, 1, 32);
        try { return Convert.ToBase64String(hash); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    // The local auth hash (iterations = 2) - stored to verify the master password offline. Uses a
    // different iteration count from the server hash so the two can never be equal (domain sep).
    public static string LocalAuthHash(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> password)
    {
        byte[] hash = Pbkdf2(masterKey, password, 2, 32);
        try { return Convert.ToBase64String(hash); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    // Stretch a 32-byte master key into a 64-byte {enc,mac} key via HKDF-Expand only (no Extract;
    // the master key is used directly as the PRK). info = "enc" / "mac".
    public static SymmetricCryptoKey StretchMasterKey(ReadOnlySpan<byte> masterKey)
    {
        byte[] prk = masterKey.ToArray();
        try
        {
            byte[] enc = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "enc"u8.ToArray());
            byte[] mac = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "mac"u8.ToArray());
            var key = new SymmetricCryptoKey(enc, mac);
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(prk); }
    }

    public static byte[] Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int length)
        => Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, length);

    // Argon2id via our own pure-managed implementation (Crypto/Argon2id.cs) - no third-party DLL, so
    // it loads under a WDAC "Microsoft signing level" policy. Verified against the RFC 9106 vector.
    public static byte[] Argon2id(ReadOnlySpan<byte> password, byte[] salt, int iterations, int memoryKiB, int parallelism, int length)
        => global::VaultType.Vault.Crypto.Argon2id.Hash(password, salt, parallelism, memoryKiB, iterations, length);
}
