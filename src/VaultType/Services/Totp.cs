using System.Security.Cryptography;

namespace VaultType.Services;

// Local TOTP (RFC 6238) - no CLI call, no clipboard, no network. Takes a Base32 secret
// or an otpauth:// URI. Works on a span so the caller can hand us the seed straight out of
// locked memory without it ever becoming a managed string on the heap.
public static class Totp
{
    public static string? Compute(ReadOnlySpan<char> secretOrOtpauth)
    {
        try
        {
            ReadOnlySpan<char> secret = secretOrOtpauth.Trim();
            string algorithm = "SHA1";
            int digits = 6, period = 30;
            bool steam = false;

            if (secret.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                if (secret.StartsWith("otpauth://totp/steam", StringComparison.OrdinalIgnoreCase)) steam = true;
                int q = secret.IndexOf('?');
                ReadOnlySpan<char> query = q >= 0 ? secret[(q + 1)..] : default;
                while (!query.IsEmpty)
                {
                    int amp = query.IndexOf('&');
                    ReadOnlySpan<char> kv = amp < 0 ? query : query[..amp];
                    query = amp < 0 ? default : query[(amp + 1)..];
                    int i = kv.IndexOf('=');
                    if (i < 0) continue;
                    ReadOnlySpan<char> k = kv[..i];
                    ReadOnlySpan<char> v = kv[(i + 1)..];
                    // The secret stays a span (Base32 needs no unescaping); the rest is non-sensitive.
                    if (k.Equals("secret", StringComparison.OrdinalIgnoreCase)) secret = v;
                    else if (k.Equals("algorithm", StringComparison.OrdinalIgnoreCase)) algorithm = v.ToString().ToUpperInvariant();
                    else if (k.Equals("digits", StringComparison.OrdinalIgnoreCase)) int.TryParse(v, out digits);
                    else if (k.Equals("period", StringComparison.OrdinalIgnoreCase)) int.TryParse(v, out period);
                }
            }
            else if (secret.StartsWith("steam://", StringComparison.OrdinalIgnoreCase))
            {
                steam = true;
                secret = secret["steam://".Length..];
            }

            if (digits <= 0) digits = 6;
            if (period <= 0) period = 30;

            byte[] key = Base32Decode(secret);   // ignores spaces and padding on its own
            if (key.Length == 0) return null;

            long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / period;
            Span<byte> msg = stackalloc byte[8];
            for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xff); counter >>= 8; }

            byte[] hash = algorithm switch
            {
                "SHA256" => HMACSHA256.HashData(key, msg),
                "SHA512" => HMACSHA512.HashData(key, msg),
                _ => HMACSHA1.HashData(key, msg),
            };
            Array.Clear(key);

            int offset = hash[^1] & 0x0f;
            int bin = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            Array.Clear(hash);

            if (steam)
            {
                const string alphabet = "23456789BCDFGHJKMNPQRTVWXY";
                var sb = new char[5];
                int val = bin;
                for (int i = 0; i < 5; i++) { sb[i] = alphabet[val % alphabet.Length]; val /= alphabet.Length; }
                return new string(sb);
            }

            int code = bin % (int)Math.Pow(10, digits);
            return code.ToString().PadLeft(digits, '0');
        }
        catch { return null; }
    }

    private static byte[] Base32Decode(ReadOnlySpan<char> s)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        if (s.IsEmpty) return Array.Empty<byte>();
        int bits = 0, value = 0;
        var output = new List<byte>(s.Length * 5 / 8 + 1);
        foreach (char c in s)
        {
            int idx = alphabet.IndexOf(char.ToUpperInvariant(c));
            if (idx < 0) continue;   // spaces, '=' padding and stray characters are skipped
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) { output.Add((byte)((value >> (bits - 8)) & 0xff)); bits -= 8; }
        }
        return output.ToArray();
    }
}
