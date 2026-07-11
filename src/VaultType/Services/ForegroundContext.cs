using System.Diagnostics;
using System.Windows.Automation;
using VaultType.Security;

namespace VaultType.Services;

// Snapshot of the active window - process, title, and the browser URL if we can read one.
public sealed class ForegroundInfo
{
    public IntPtr Hwnd;
    public string Exe = "";     // e.g. "brave.exe"
    public string Title = "";
    public string? Url;         // only for recognised browsers
}

public static class ForegroundContext
{
    // Chromium- and Firefox-based browsers whose address bar is readable via UIA.
    private static readonly string[] Browsers =
    {
        "brave", "chrome", "msedge", "opera", "opera_gx", "vivaldi", "chromium", "thorium", "arc",
        "firefox", "librewolf", "waterfox", "floorp", "zen", "iexplore"
    };

    // fast path - window handle, process and title, no UI Automation
    public static ForegroundInfo CaptureWindow() => FromWindow(Native.GetForegroundWindow());

    // build the context for a given window handle (used by the tray trigger)
    public static ForegroundInfo FromWindow(IntPtr hwnd)
    {
        var info = new ForegroundInfo { Hwnd = hwnd };
        if (hwnd == IntPtr.Zero) return info;
        info.Title = GetTitle(hwnd);
        info.Exe = GetExe(hwnd);
        return info;
    }

    // slow: pull the browser URL out via UI Automation. Call this off the UI thread.
    public static string? ReadUrl(IntPtr hwnd, string exe)
    {
        if (hwnd == IntPtr.Zero) return null;
        string name = exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe[..^4] : exe;
        if (!Array.Exists(Browsers, b => string.Equals(b, name, StringComparison.OrdinalIgnoreCase))) return null;
        return TryGetUrl(hwnd);
    }

    private static string GetTitle(IntPtr hwnd)
    {
        int len = Native.GetWindowTextLength(hwnd);
        if (len <= 0) return "";
        var buf = new char[len + 1];
        int n = Native.GetWindowText(hwnd, buf, buf.Length);
        return new string(buf, 0, n);
    }

    private static string GetExe(IntPtr hwnd)
    {
        try
        {
            Native.GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid == 0) return "";
            using var p = Process.GetProcessById((int)pid);
            return (p.MainModule?.ModuleName) ?? (p.ProcessName + ".exe");
        }
        catch
        {
            try
            {
                Native.GetWindowThreadProcessId(hwnd, out uint pid);
                using var p = Process.GetProcessById((int)pid);
                return p.ProcessName + ".exe";
            }
            catch { return ""; }
        }
    }

    // read the URL from the address bar (an Edit control exposing ValuePattern)
    private static string? TryGetUrl(IntPtr hwnd)
    {
        try
        {
            var root = AutomationElement.FromHandle(hwnd);
            if (root == null) return null;

            var cond = new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit);

            // FindFirst stops at the first Edit - the omnibox is near the top of the tree,
            // so this beats walking every Edit in Chromium's enormous tree.
            var first = root.FindFirst(TreeScope.Descendants, cond);
            if (first != null && TryReadUrl(first, out string url)) return url;

            // Fallback: scan the remaining edits.
            var edits = root.FindAll(TreeScope.Descendants, cond);
            foreach (AutomationElement e in edits)
                if (TryReadUrl(e, out url)) return url;
        }
        catch { /* UIA unavailable / window gone */ }
        return null;
    }

    private static bool TryReadUrl(AutomationElement e, out string url)
    {
        url = "";
        if (e.TryGetCurrentPattern(ValuePattern.Pattern, out object pat))
        {
            string val = (((ValuePattern)pat).Current.Value ?? "").Trim();
            if (LooksLikeUrl(val)) { url = Normalize(val); return true; }
        }
        return false;
    }

    private static bool LooksLikeUrl(string v)
    {
        if (string.IsNullOrWhiteSpace(v)) return false;
        if (v.Contains(' ')) return false;                     // placeholder text ("Search ...")
        if (v.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return true;
        if (v.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return true;
        return v.Contains('.') && !v.Contains("://");          // "github.com/..." without a scheme
    }

    private static string Normalize(string v)
        => v.Contains("://") ? v : "https://" + v;
}
