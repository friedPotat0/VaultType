using System.IO;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace VaultType.Vault.Crypto;

// Bitwarden's fingerprint phrase, as shown on both sides of a "log in with device" request. The user
// compares the two; that comparison is the only thing that ties the requester's public key to the
// browser in front of them (the key exchange itself is unauthenticated).
//
//   PRK  = SHA-256(public key, SPKI DER)
//   OKM  = HKDF-Expand(PRK, info = lowercased account email, 32 bytes)   - no Extract step
//   words: OKM as an unsigned big-endian integer, five times "n % 7776, n /= 7776", each remainder
//          indexing the EFF long word list, least significant first, joined with "-".
public static class FingerprintPhrase
{
    private const int Words = 5;   // ceil(64 bits of entropy / log2(7776))

    private static readonly Lazy<string[]> WordList = new(LoadWordList);

    public static string For(string email, byte[] publicKeySpki)
    {
        byte[] prk = SHA256.HashData(publicKeySpki);
        byte[] okm = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32,
            Encoding.UTF8.GetBytes(email.ToLowerInvariant()));

        var list = WordList.Value;
        var n = new BigInteger(okm, isUnsigned: true, isBigEndian: true);
        var words = new string[Words];
        for (int i = 0; i < Words; i++)
        {
            words[i] = list[(int)(n % list.Length)];
            n /= list.Length;
        }
        return string.Join("-", words);
    }

    // EFF long word list (7776 words, "abacus" .. "zoom"), embedded one word per line.
    private static string[] LoadWordList()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("VaultType.Assets.eff_large_wordlist.txt")
            ?? throw new InvalidOperationException("Word list missing.");
        using var r = new StreamReader(s, Encoding.UTF8);
        var words = r.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length != 7776) throw new InvalidOperationException("Word list damaged.");
        return words;
    }
}
