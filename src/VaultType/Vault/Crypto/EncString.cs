using System.Security.Cryptography;

namespace VaultType.Vault.Crypto;

// Bitwarden's "EncString" wire format: "<encType>.<b64>|<b64>|<b64>".
//   0.iv|data          AES-256-CBC, no MAC (legacy)
//   1.iv|data|mac      AES-128-CBC + HMAC-SHA256 (legacy, no longer produced)
//   2.iv|data|mac      AES-256-CBC + HMAC-SHA256   (the common case)
//   3.data             RSA-2048 OAEP-SHA256
//   4.data             RSA-2048 OAEP-SHA1          (org keys, auth-request/passkey wraps)
//   5.data|mac / 6     RSA + HMAC (deprecated, unused)
// We implement 0/2 (symmetric) and 3/4 (RSA). MAC is verified constant-time before decrypt.
// Type 1 (AES-128) is parsed but rejected on decrypt: modern vaults never emit it and our keys
// are always 32 bytes, so decrypting it with a 32-byte key would silently use the wrong width.
public sealed class EncString
{
    public int Type { get; }
    public byte[] Iv { get; }
    public byte[] Data { get; }
    public byte[]? Mac { get; }

    private EncString(int type, byte[] iv, byte[] data, byte[]? mac)
    {
        Type = type; Iv = iv; Data = data; Mac = mac;
    }

    public static EncString? TryParse(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        try { return Parse(s); } catch { return null; }
    }

    public static EncString Parse(string s)
    {
        int dot = s.IndexOf('.');
        int type;
        string body;
        if (dot >= 0 && dot <= 2 && int.TryParse(s.AsSpan(0, dot), out type))
        {
            body = s[(dot + 1)..];
        }
        else
        {
            // Very old vaults stored type-0 without the "0." prefix.
            type = 0;
            body = s;
        }

        string[] parts = body.Split('|');
        switch (type)
        {
            case 0: // iv|data
                if (parts.Length < 2) throw new FormatException("EncString type 0 needs iv|data.");
                return new EncString(0, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), null);
            case 1:
            case 2: // iv|data|mac
                if (parts.Length < 3) throw new FormatException($"EncString type {type} needs iv|data|mac.");
                return new EncString(type, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), Convert.FromBase64String(parts[2]));
            case 3:
            case 4: // data only
                return new EncString(type, Array.Empty<byte>(), Convert.FromBase64String(parts[0]), null);
            case 5:
            case 6: // data|mac
                if (parts.Length < 2) throw new FormatException($"EncString type {type} needs data|mac.");
                return new EncString(type, Array.Empty<byte>(), Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
            default:
                throw new NotSupportedException($"Unsupported EncString type {type}.");
        }
    }

    public bool IsSymmetric => Type is 0 or 1 or 2;
    public bool IsRsa => Type is 3 or 4;

    // Decrypt a symmetric (type 0/2) EncString with the given key. Verifies the HMAC first (type 2).
    public byte[] DecryptSymmetric(SymmetricCryptoKey key)
    {
        if (!IsSymmetric) throw new CryptographicException($"EncString type {Type} is not symmetric.");

        // Type 1 (AES-128-CBC) uses a 16-byte enc key, but SymmetricCryptoKey always carries a
        // 32-byte key. Rather than silently decrypt with the wrong key width, reject it outright -
        // modern Bitwarden vaults do not produce type 1.
        if (Type == 1)
            throw new CryptographicException("EncString type 1 (AES-128-CBC) is not supported.");

        if (Type == 2)
        {
            if (Mac == null) throw new CryptographicException("EncString is missing its MAC.");
            if (!key.HasMac) throw new CryptographicException("Key has no MAC part but EncString requires one.");
            // HMAC-SHA256 over iv || data
            Span<byte> computed = stackalloc byte[32];
            using (var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key.MacKey))
            {
                h.AppendData(Iv);
                h.AppendData(Data);
                h.GetHashAndReset(computed);
            }
            if (!CryptographicOperations.FixedTimeEquals(computed, Mac))
                throw new CryptographicException("EncString MAC verification failed (wrong key or tampered data).");
        }

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key.EncKey.ToArray();
        aes.IV = Iv;
        try
        {
            return aes.DecryptCbc(Data, Iv, PaddingMode.PKCS7);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aes.Key);
        }
    }

    public string DecryptToString(SymmetricCryptoKey key)
    {
        byte[] pt = DecryptSymmetric(key);
        try { return System.Text.Encoding.UTF8.GetString(pt); }
        finally { CryptographicOperations.ZeroMemory(pt); }
    }

    // Decrypt an RSA (type 3/4) EncString with an RSA private key.
    public byte[] DecryptRsa(RSA rsa)
    {
        RSAEncryptionPadding padding = Type switch
        {
            3 => RSAEncryptionPadding.OaepSHA256,
            4 => RSAEncryptionPadding.OaepSHA1,
            _ => throw new CryptographicException($"EncString type {Type} is not RSA."),
        };
        return rsa.Decrypt(Data, padding);
    }

    // ---- encryption (for editing items) ----

    // Encrypt bytes as a type-2 EncString with a random IV.
    public static string EncryptSymmetric(ReadOnlySpan<byte> plaintext, SymmetricCryptoKey key)
    {
        if (!key.HasMac) throw new CryptographicException("A MAC key is required to produce a type-2 EncString.");
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] cipher;
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key.EncKey.ToArray();
            aes.IV = iv;
            try { cipher = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7); }
            finally { CryptographicOperations.ZeroMemory(aes.Key); }
        }
        Span<byte> mac = stackalloc byte[32];
        using (var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key.MacKey))
        {
            h.AppendData(iv);
            h.AppendData(cipher);
            h.GetHashAndReset(mac);
        }
        return $"2.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(cipher)}|{Convert.ToBase64String(mac)}";
    }

    public static string EncryptString(string plaintext, SymmetricCryptoKey key)
    {
        byte[] pt = System.Text.Encoding.UTF8.GetBytes(plaintext);
        try { return EncryptSymmetric(pt, key); }
        finally { CryptographicOperations.ZeroMemory(pt); }
    }
}
