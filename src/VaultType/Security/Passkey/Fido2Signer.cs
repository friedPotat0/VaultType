using System.Security.Cryptography;

namespace VaultType.Security.Passkey;

// ES256 signing for assertions. The PKCS#8 private key stays inside a LockedBuffer for the moment
// of the signature; the WebAuthn signature format for ES256 is ASN.1 DER (RFC 3279), which is what
// SignData produces by default.
internal static class Fido2Signer
{
    internal static byte[]? SignAssertion(SecretBox privateKey, SecretProtector protector,
                                          byte[] authData, byte[] clientDataHash)
    {
        byte[] message = new byte[authData.Length + clientDataHash.Length];
        authData.CopyTo(message, 0);
        clientDataHash.CopyTo(message, authData.Length);

        using var buf = protector.Reveal(privateKey);
        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(buf.Span[..privateKey.Cipher.Length], out _);
        }
        catch (CryptographicException ex)
        {
            PasskeyLog.Write($"sign: PKCS#8 import failed: {ex.Message}");
            return null;
        }
        return ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}
