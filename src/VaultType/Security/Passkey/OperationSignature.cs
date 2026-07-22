using System.Security.Cryptography;

namespace VaultType.Security.Passkey;

// Windows signs every plugin operation request so a plugin can tell a real ceremony from a local
// process poking at its COM class. The public key comes from WebAuthNPluginGetOperationSigningPublicKey
// (same value webauthn.dll returns from AddAuthenticator).
//
// The exact bytes Windows signs are not specified in the public headers. Confirmed on-device
// (Windows 11 26200, webauthn.dll 26100.8117, 2026-07-20): the pre-image is the raw encoded
// request, ECDSA P-256/SHA-256 in IEEE P1363 (r||s) format. Enforce is on - an unverifiable
// request is rejected.
internal static class OperationSignature
{
    private const bool Enforce = true;

    internal static bool Verify(PluginOperationRequest req, byte[] encodedRequest)
    {
        if (req.CbRequestSignature == 0 || req.PbRequestSignature == IntPtr.Zero)
            return !Enforce;

        byte[] sig = new byte[req.CbRequestSignature];
        System.Runtime.InteropServices.Marshal.Copy(req.PbRequestSignature, sig, 0, sig.Length);

        try
        {
            using var ecdsa = LoadPublicKey();
            if (ecdsa == null)
                return !Enforce;

            if (ecdsa.VerifyData(encodedRequest, sig, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return true;
            }

            return !Enforce;
        }
        catch
        {
            return !Enforce;
        }
    }

    // The key blob's encoding isn't documented either; try SubjectPublicKeyInfo (DER) first, then
    // the raw BCRYPT_ECCKEY_BLOB layout webauthn.dll uses elsewhere.
    private static ECDsa? LoadPublicKey()
    {
        var clsid = PasskeyIds.Clsid;
        int hr = PasskeyNative.WebAuthNPluginGetOperationSigningPublicKey(ref clsid, out uint cb, out IntPtr pb);
        if (hr != PasskeyNative.S_OK || pb == IntPtr.Zero || cb == 0)
            return null;

        byte[] blob = new byte[cb];
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(pb, blob, 0, blob.Length);
        }
        finally { PasskeyNative.WebAuthNPluginFreePublicKeyResponse(pb); }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(blob, out _);
            return ecdsa;
        }
        catch (CryptographicException) { }

        // BCRYPT_ECCKEY_BLOB: dwMagic (4) | cbKey (4) | X | Y, both big-endian and cbKey long.
        try
        {
            if (blob.Length > 8)
            {
                int cbKey = BitConverter.ToInt32(blob, 4);
                if (cbKey > 0 && blob.Length >= 8 + 2 * cbKey)
                {
                    ecdsa.ImportParameters(new ECParameters
                    {
                        Curve = cbKey switch
                        {
                            32 => ECCurve.NamedCurves.nistP256,
                            48 => ECCurve.NamedCurves.nistP384,
                            _ => ECCurve.NamedCurves.nistP521,
                        },
                        Q = new ECPoint
                        {
                            X = blob[8..(8 + cbKey)],
                            Y = blob[(8 + cbKey)..(8 + 2 * cbKey)],
                        },
                    });
                    return ecdsa;
                }
            }
        }
        catch (CryptographicException) { }

        ecdsa.Dispose();
        return null;
    }
}
