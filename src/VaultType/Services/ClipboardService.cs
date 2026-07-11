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
        string seed = Encoding.UTF8.GetString(buf.Span.Slice(0, item.TotpSecret.Cipher.Length));
        string? code = Totp.Compute(seed);
        if (code != null) Set(code, clearSeconds);
    }

    private static void Set(string text, int clearSeconds)
    {
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); } catch { return; }
        ScheduleClear(clearSeconds);
    }

    private static void ScheduleClear(int seconds)
    {
        _timer?.Stop();
        if (seconds <= 0) return;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(seconds) };
        _timer.Tick += (_, __) => { _timer!.Stop(); ClearNow(); };
        _timer.Start();
    }

    public static void ClearNow()
    {
        _timer?.Stop();
        try { Clipboard.Clear(); } catch { }
    }
}
