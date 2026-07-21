using System.Numerics;
using System.Security.Cryptography;

namespace VaultType.Vault.Crypto;

// Pure-managed Ed25519 (RFC 8032) signing. Lives in VaultType's own assembly so it loads under a
// WDAC "Microsoft signing level" policy that blocks third-party-signed native/managed DLLs (which
// is why the BouncyCastle dependency was removed). Verified against the RFC 8032 §7.1 test vectors
// (see CryptoSelfTest).
//
// Field/scalar arithmetic uses BigInteger: far simpler and easier to audit than a packed-limb
// implementation, and plenty fast for the SSH agent's occasional signatures (a handful per session).
// Only signing is implemented - the SSH agent never verifies - so no point decompression is needed.
//
// Note: the BigInteger ScalarMult/ModInverse are data-dependent, i.e. NOT constant-time, so they
// leak timing on the secret scalar. This is a deliberately accepted trade-off for this threat model
// (a local SSH agent producing a handful of signatures per session, no remote timing oracle); do
// not "fix" it by hand-rolling constant-time field arithmetic - that is far more likely to
// introduce a correctness bug than to close a practically exploitable channel.
internal static class Ed25519
{
    // p = 2^255 - 19
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    // group order L = 2^252 + 27742317777372353535851937790883648493
    private static readonly BigInteger L =
        BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    // curve constant d = -121665/121666 mod p
    private static readonly BigInteger D =
        BigInteger.Parse("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    // base point B
    private static readonly BigInteger Bx =
        BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    private static readonly BigInteger By =
        BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");

    // Sign message with a 32-byte Ed25519 seed (the raw private key), returning the 64-byte signature.
    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes", nameof(seed));

        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(seed, h);

        // scalar a from the clamped lower half
        Span<byte> aBytes = stackalloc byte[32];
        h[..32].CopyTo(aBytes);
        aBytes[0] &= 248;
        aBytes[31] &= 127;
        aBytes[31] |= 64;
        BigInteger a = LeToInt(aBytes);

        byte[] prefix = h[32..].ToArray();
        byte[] publicKey = EncodePoint(ScalarMultBase(a));

        // r = H(prefix || M) mod L ; R = r*B
        BigInteger r = ReduceToScalar(Sha512(prefix, message));
        byte[] rEnc = EncodePoint(ScalarMultBase(r));

        // k = H(R || A || M) mod L ; S = (r + k*a) mod L
        BigInteger k = ReduceToScalar(Sha512(rEnc, publicKey, message));
        BigInteger s = Mod(r + k * a, L);

        var sig = new byte[64];
        rEnc.CopyTo(sig, 0);
        IntToLe(s, sig.AsSpan(32, 32));
        return sig;
    }

    // Derive the 32-byte public key from a seed (used by the known-answer self-test).
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
    {
        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(seed, h);
        Span<byte> aBytes = stackalloc byte[32];
        h[..32].CopyTo(aBytes);
        aBytes[0] &= 248;
        aBytes[31] &= 127;
        aBytes[31] |= 64;
        return EncodePoint(ScalarMultBase(LeToInt(aBytes)));
    }

    // --- group arithmetic in extended homogeneous coordinates (X, Y, Z, T), x=X/Z, y=Y/Z, XY=ZT ---

    private readonly record struct Pt(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    private static readonly Pt Identity = new(0, 1, 1, 0);
    private static Pt Base => new(Bx, By, 1, Mod(Bx * By, P));

    // RFC 8032 §5.1.4 unified addition (also correct for doubling).
    private static Pt Add(in Pt p1, in Pt p2)
    {
        BigInteger a = Mod((p1.Y - p1.X) * (p2.Y - p2.X), P);
        BigInteger b = Mod((p1.Y + p1.X) * (p2.Y + p2.X), P);
        BigInteger c = Mod(p1.T * 2 * D * p2.T, P);
        BigInteger d = Mod(p1.Z * 2 * p2.Z, P);
        BigInteger e = b - a;
        BigInteger f = d - c;
        BigInteger g = d + c;
        BigInteger hh = b + a;
        return new Pt(Mod(e * f, P), Mod(g * hh, P), Mod(f * g, P), Mod(e * hh, P));
    }

    private static Pt ScalarMultBase(BigInteger e) => ScalarMult(e, Base);

    private static Pt ScalarMult(BigInteger e, in Pt point)
    {
        var result = Identity;
        var acc = point;
        // process the scalar low-to-high, doubling the accumulator each step
        for (int i = 0; i < 256; i++)
        {
            if (!(e >> i & 1).IsZero) result = Add(result, acc);
            acc = Add(acc, acc);
        }
        return result;
    }

    private static byte[] EncodePoint(in Pt p)
    {
        BigInteger zInv = ModInverse(p.Z, P);
        BigInteger x = Mod(p.X * zInv, P);
        BigInteger y = Mod(p.Y * zInv, P);
        var outp = new byte[32];
        IntToLe(y, outp);
        // top bit carries the parity (LSB) of x
        outp[31] |= (byte)((x & 1) << 7);
        return outp;
    }

    // --- scalar/field helpers ---

    private static BigInteger ReduceToScalar(byte[] hash64) => Mod(LeToInt(hash64), L);

    private static byte[] Sha512(byte[] a, ReadOnlySpan<byte> b)
    {
        using var sha = SHA512.Create();
        sha.TransformBlock(a, 0, a.Length, null, 0);
        byte[] bb = b.ToArray();
        sha.TransformBlock(bb, 0, bb.Length, null, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    private static byte[] Sha512(byte[] a, byte[] b, ReadOnlySpan<byte> c)
    {
        using var sha = SHA512.Create();
        sha.TransformBlock(a, 0, a.Length, null, 0);
        sha.TransformBlock(b, 0, b.Length, null, 0);
        byte[] cc = c.ToArray();
        sha.TransformBlock(cc, 0, cc.Length, null, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    private static BigInteger Mod(BigInteger x, BigInteger m)
    {
        BigInteger r = x % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger m) => BigInteger.ModPow(Mod(a, m), m - 2, m);

    // little-endian byte[] -> non-negative BigInteger
    private static BigInteger LeToInt(ReadOnlySpan<byte> le)
    {
        Span<byte> tmp = stackalloc byte[le.Length + 1];
        le.CopyTo(tmp);
        tmp[le.Length] = 0;                 // force positive
        return new BigInteger(tmp);
    }

    // non-negative BigInteger -> fixed-length little-endian span
    private static void IntToLe(BigInteger v, Span<byte> dest)
    {
        dest.Clear();
        byte[] le = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        int n = Math.Min(le.Length, dest.Length);
        le.AsSpan(0, n).CopyTo(dest);
    }
}
