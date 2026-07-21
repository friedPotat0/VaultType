using System.Security.Cryptography;

namespace VaultType.Vault.Crypto;

// A Bitwarden symmetric key: a 32-byte AES key, optionally paired with a 32-byte HMAC key.
// Legacy type-0 accounts have only the encryption key (no MAC); everything modern is 64 bytes
// (enc || mac). The raw bytes are wiped on Dispose. These live only while a vault is unlocked.
public sealed class SymmetricCryptoKey : IDisposable
{
    private byte[]? _enc;   // 32 bytes
    private byte[]? _mac;   // 32 bytes, or null for MAC-less (type 0) keys

    public SymmetricCryptoKey(byte[] enc, byte[]? mac)
    {
        _enc = enc;
        _mac = mac;
    }

    // Split a 64-byte (enc||mac) or 32-byte (enc only) blob into a key. Takes a copy so the
    // caller can wipe its own buffer.
    public static SymmetricCryptoKey FromRaw(ReadOnlySpan<byte> raw)
    {
        if (raw.Length == 64)
            return new SymmetricCryptoKey(raw[..32].ToArray(), raw[32..].ToArray());
        if (raw.Length == 32)
            return new SymmetricCryptoKey(raw.ToArray(), null);
        throw new CryptographicException($"Unexpected symmetric key length {raw.Length} (want 32 or 64).");
    }

    public ReadOnlySpan<byte> EncKey => _enc ?? throw new ObjectDisposedException(nameof(SymmetricCryptoKey));
    public bool HasMac => _mac != null;
    public ReadOnlySpan<byte> MacKey => _mac ?? throw new CryptographicException("Key has no MAC part.");

    public void Dispose()
    {
        if (_enc != null) { CryptographicOperations.ZeroMemory(_enc); _enc = null; }
        if (_mac != null) { CryptographicOperations.ZeroMemory(_mac); _mac = null; }
    }
}
