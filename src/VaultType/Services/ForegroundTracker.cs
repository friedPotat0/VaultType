using VaultType.Security;

namespace VaultType.Services;

// Keeps track of the last real foreground window (ignoring our own windows and the shell),
// so the tray trigger can type into whatever the user had active before they clicked.
public sealed class ForegroundTracker : IDisposable
{
    private readonly uint _ownPid = (uint)Environment.ProcessId;
    private readonly Native.WinEventDelegate _callback;
    private IntPtr _hook;

    public IntPtr LastWindow { get; private set; }

    public ForegroundTracker()
    {
        _callback = OnForeground; // keep the delegate alive for the hook's lifetime
        _hook = Native.SetWinEventHook(
            Native.EVENT_SYSTEM_FOREGROUND, Native.EVENT_SYSTEM_FOREGROUND, IntPtr.Zero,
            _callback, 0, 0, Native.WINEVENT_OUTOFCONTEXT | Native.WINEVENT_SKIPOWNPROCESS);
    }

    private void OnForeground(IntPtr hook, uint ev, IntPtr hwnd, int idObject, int idChild, uint thread, uint time)
    {
        if (hwnd == IntPtr.Zero || idObject != 0) return; // OBJID_WINDOW only
        Native.GetWindowThreadProcessId(hwnd, out uint pid);
        if (pid == _ownPid) return;
        if (IsShell(hwnd)) return;
        LastWindow = hwnd;
    }

    private static bool IsShell(IntPtr hwnd)
    {
        var buf = new char[256];
        int n = Native.GetClassName(hwnd, buf, buf.Length);
        string cls = new string(buf, 0, n);
        return cls is "Shell_TrayWnd" or "Shell_SecondaryTrayWnd" or "Progman" or "WorkerW"
            or "NotifyIconOverflowWindow" or "TopLevelWindowForOverflowXamlIsland"
            or "Windows.UI.Core.CoreWindow" or "XamlExplorerHostIslandWindow";
    }

    public void Dispose()
    {
        if (_hook != IntPtr.Zero) { Native.UnhookWinEvent(_hook); _hook = IntPtr.Zero; }
    }
}
