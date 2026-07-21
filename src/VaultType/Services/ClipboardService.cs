using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Threading;
using VaultType.Models;
using VaultType.Security;

namespace VaultType.Services;

// Copies a field to the clipboard and wipes it again after a timeout (KeePass-style). Secrets
// are only decrypted for the moment of the copy. The catch: the OS clipboard keeps a plaintext
// copy until it's cleared - that's just the price of "copy to clipboard".
public static class ClipboardService
{
    private static DispatcherTimer? _timer;

    // SHA-256 of the text we last put on the clipboard. We keep only the hash (never the
    // plaintext) so the auto-clear can tell "our" secret apart from whatever the user might
    // have copied in the meantime, without holding the secret around past the copy.
    private static byte[]? _lastHash;

    public static void CopyUsername(VaultItem item, int clearSeconds) => Set(item.Username, clearSeconds);

    public static void CopyPassword(VaultItem item, SecretProtector p, int clearSeconds)
    {
        if (item.Password == null || !p.IsActive) return;
        using var buf = p.Reveal(item.Password);
        string s = Encoding.UTF8.GetString(buf.Span.Slice(0, item.Password.Cipher.Length));
        Set(s, clearSeconds);
    }

    public static void CopyTotp(VaultItem item, SecretProtector p, int clearSeconds)
    {
        if (item.TotpSecret == null || !p.IsActive) return;
        using var buf = p.Reveal(item.TotpSecret);
        int byteLen = item.TotpSecret.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(buf.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);   // seed stays in locked memory, not a managed string
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(buf.Span.Slice(0, byteLen), charSpan);

        string? code = Totp.Compute(charSpan.Slice(0, n));
        if (code != null) Set(code, clearSeconds);
    }

    // The clipboard and the auto-clear timer must live on the UI/STA dispatcher, otherwise
    // Clipboard.SetText can throw and a DispatcherTimer created off the UI thread would bind to
    // a dispatcher whose Tick never fires - leaving the secret on the clipboard forever.
    private static Dispatcher? Ui => Application.Current?.Dispatcher;

    private static void Set(string text, int clearSeconds)
    {
        if (string.IsNullOrEmpty(text)) return;
        var ui = Ui;
        if (ui == null) return;               // no UI thread -> nowhere safe to touch the clipboard
        if (ui.CheckAccess()) SetCore(text, clearSeconds);
        else ui.Invoke(() => SetCore(text, clearSeconds));
    }

    // Always runs on the UI/STA thread.
    private static void SetCore(string text, int clearSeconds)
    {
        try { Clipboard.SetText(text); }
        catch { return; }
        _lastHash = Hash(text);
        ScheduleClear(clearSeconds);
    }

    private static void ScheduleClear(int seconds)
    {
        _timer?.Stop();
        _timer = null;
        if (seconds <= 0) return;
        var ui = Ui;
        if (ui == null) return;
        // Bind the timer explicitly to the UI dispatcher so Tick fires regardless of which
        // thread asked for the copy.
        _timer = new DispatcherTimer(DispatcherPriority.Normal, ui) { Interval = TimeSpan.FromSeconds(seconds) };
        _timer.Tick += (_, __) => { _timer?.Stop(); ClearNow(); };
        _timer.Start();
    }

    public static void ClearNow()
    {
        var ui = Ui;
        if (ui != null && !ui.CheckAccess()) { ui.Invoke(ClearNow); return; }

        _timer?.Stop();
        _timer = null;

        byte[]? expected = _lastHash;
        _lastHash = null;
        if (expected == null) return;         // nothing of ours to clear

        try
        {
            // Only wipe if the clipboard still holds exactly what we put there. If the user
            // copied something else in the meantime, its hash won't match and we leave it alone.
            if (!Clipboard.ContainsText()) return;
            byte[] current = Hash(Clipboard.GetText());
            if (CryptographicOperations.FixedTimeEquals(current, expected))
                Clipboard.Clear();
        }
        catch { }
    }

    // SHA-256 of the UTF-8 text; the transient plaintext byte buffer is zeroed straight after.
    private static byte[] Hash(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        try { return SHA256.HashData(bytes); }
        finally { Array.Clear(bytes); }
    }
}
