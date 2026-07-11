using System.Security.Cryptography;

namespace VaultType.Services;

// Local TOTP (RFC 6238) - no CLI call, no clipboard, no network. Takes a Base32 secret
// or an otpauth:// URI.
public static class Totp
{
    public static string? Compute(string secretOrOtpauth)
    {
        try
        {
            string secret = secretOrOtpauth.Trim();
            string algorithm = "SHA1";
            int digits = 6, period = 30;
            bool steam = false;

            if (secret.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                if (secret.StartsWith("otpauth://totp/steam", StringComparison.OrdinalIgnoreCase)) steam = true;
                int q = secret.IndexOf('?');
                var query = q >= 0 ? secret[(q + 1)..] : "";
                foreach (var kv in query.Split('&'))
                {
                    var i = kv.IndexOf('=');
                    if (i < 0) continue;
                    var k = kv[..i].ToLowerInvariant();
                    var v = Uri.UnescapeDataString(kv[(i + 1)..]);
                    switch (k)
                    {
                        case "secret": secret = v; break;
                        case "algorithm": algorithm = v.ToUpperInvariant(); break;
                        case "digits": int.TryParse(v, out digits); break;
                        case "period": int.TryParse(v, out period); break;
                    }
                }
            }
            else if (secret.StartsWith("steam://", StringComparison.OrdinalIgnoreCase))
            {
                steam = true;
                secret = secret["steam://".Length..];
            }

            if (digits <= 0) digits = 6;
            if (period <= 0) period = 30;

            byte[] key = Base32Decode(secret.Replace(" ", ""));
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

    private static byte[] Base32Decode(string s)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        s = s.TrimEnd('=').ToUpperInvariant();
        if (s.Length == 0) return Array.Empty<byte>();
        int bits = 0, value = 0;
        var output = new List<byte>(s.Length * 5 / 8 + 1);
        foreach (char c in s)
        {
            int idx = alphabet.IndexOf(c);
            if (idx < 0) continue;
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) { output.Add((byte)((value >> (bits - 8)) & 0xff)); bits -= 8; }
        }
        return output.ToArray();
    }
}
