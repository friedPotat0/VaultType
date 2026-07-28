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

    // Copy one field of an entry. Putting a secret on the clipboard inevitably turns it into a
    // managed string - that is the price of "copy", and why the auto-clear below exists.
    public static void Copy(VaultItem item, ItemField field, SecretProtector p, int clearSeconds)
    {
        var card = item.Card;
        var id = item.Identity;

        switch (field)
        {
            case ItemField.Username: Set(item.Username, clearSeconds); break;
            case ItemField.Password: Set(Plain(item.Password, p), clearSeconds); break;
            case ItemField.Totp: CopyTotp(item, p, clearSeconds); break;

            case ItemField.CardNumber: Set(Plain(card?.Number, p), clearSeconds); break;
            case ItemField.CardCode: Set(Plain(card?.Code, p), clearSeconds); break;
            case ItemField.CardHolder: Set(card?.CardholderName ?? "", clearSeconds); break;
            case ItemField.CardExpiry: Set(Expiry(card, p), clearSeconds); break;

            case ItemField.IdName: Set(id?.FullName ?? "", clearSeconds); break;
            case ItemField.IdEmail: Set(Plain(id?.Email, p), clearSeconds); break;
            case ItemField.IdPhone: Set(Plain(id?.Phone, p), clearSeconds); break;
            case ItemField.IdAddress: Set(Address(id, p), clearSeconds); break;
        }
    }

    // "MM/YY" from the two protected expiry parts, matching what the typing engine produces.
    private static string Expiry(CardData? card, SecretProtector p)
    {
        if (card == null) return "";
        string m = Plain(card.ExpMonth, p);
        string y = Plain(card.ExpYear, p);
        if (m.Length == 1) m = "0" + m;
        if (y.Length > 2) y = y[^2..];
        return m.Length == 0 && y.Length == 0 ? "" : $"{m}/{y}";
    }

    private static string Address(IdentityData? id, SecretProtector p)
    {
        if (id == null) return "";
        var parts = new List<string>();
        void Add(string s) { if (s.Length > 0) parts.Add(s); }
        Add(Plain(id.Address1, p));
        Add(Plain(id.Address2, p));
        string zip = Plain(id.PostalCode, p), city = Plain(id.City, p);
        Add(string.Join(" ", new[] { zip, city }.Where(x => x.Length > 0)));
        Add(Plain(id.Country, p));
        return string.Join(Environment.NewLine, parts);
    }

    private static string Plain(SecretBox? box, SecretProtector p)
    {
        if (box == null || !p.IsActive) return "";
        using var buf = p.Reveal(box);
        return Encoding.UTF8.GetString(buf.Span.Slice(0, box.Cipher.Length));
    }

    private static void CopyTotp(VaultItem item, SecretProtector p, int clearSeconds)
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
