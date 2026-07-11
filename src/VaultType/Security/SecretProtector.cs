using System.Security.Cryptography;

namespace VaultType.Security;

// Keeps every secret (passwords, TOTP seeds) AES-256-GCM encrypted in RAM under an
// ephemeral key that lives in locked memory. Plaintext only appears for the moment we
// type it, inside a LockedBuffer. Locking wipes the key, so any leftover ciphertext is junk.
public sealed class SecretProtector : IDisposable
{
    private const int KeyLen = 32, NonceLen = 12, TagLen = 16;
    private LockedBuffer? _key;

    public SecretProtector()
    {
        _key = new LockedBuffer(KeyLen);
        RandomNumberGenerator.Fill(_key.Span);
    }

    public bool IsActive => _key != null;

    // encrypt plaintext bytes coming out of a locked buffer
    public SecretBox Protect(ReadOnlySpan<byte> plaintext)
    {
        if (_key == null) throw new InvalidOperationException("Protector is locked");
        var nonce = new byte[NonceLen];
        RandomNumberGenerator.Fill(nonce);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagLen];
        using var gcm = new AesGcm(_key.Span, TagLen);
        gcm.Encrypt(nonce, plaintext, cipher, tag);
        return new SecretBox(nonce, cipher, tag);
    }

    // decrypt into a locked buffer - caller has to dispose it
    public LockedBuffer Reveal(SecretBox box)
    {
        if (_key == null) throw new InvalidOperationException("Protector is locked");
        var outBuf = new LockedBuffer(Math.Max(1, box.Cipher.Length));
        using var gcm = new AesGcm(_key.Span, TagLen);
        gcm.Decrypt(box.Nonce, box.Cipher, box.Tag, outBuf.Span.Slice(0, box.Cipher.Length));
        return outBuf;
    }

    public void Dispose() { _key?.Dispose(); _key = null; }
}

// Ciphertext blob - meaningless without the ephemeral key.
public sealed class SecretBox
{
    public readonly byte[] Nonce, Cipher, Tag;
    public SecretBox(byte[] nonce, byte[] cipher, byte[] tag) { Nonce = nonce; Cipher = cipher; Tag = tag; }
}
