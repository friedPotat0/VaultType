using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VaultType.Security.Passkey;

// Diagnostics for the passkey plugin. The ceremony runs in a separate, windowless process that
// Windows starts on demand, so a log file is the only practical way to see what happened.
// Never log credential material - and never the plaintext RP id / username either: the log lives
// in %TEMP% with weak protection, so identifiers that form a behavioural profile are redacted.
internal static class PasskeyLog
{
    private static readonly object Gate = new();

    internal static string Path => System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vaulttype-passkey.log");

    // A short, stable, non-reversible tag for an RP id / username, so entries stay correlatable
    // within a session without writing the plaintext domain or account name to disk.
    internal static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(value), hash);
        return "#" + Convert.ToHexString(hash[..4]);
    }

    internal static void Write(string message)
    {
        try
        {
            lock (Gate)
                File.AppendAllText(Path, $"[{DateTime.Now:s}] [{Environment.ProcessId}] {message}\n");
        }
        catch { }
    }
}
