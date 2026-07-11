namespace VaultType.Security;

// Process hardening + debugger detection.
internal static class ProcessHardening
{
    public static void Apply(bool antiDebugger)
    {
        // Block legacy injection: AppInit_DLLs, global SetWindowsHookEx hooks and
        // IME injection can no longer load into this process.
        try
        {
            uint flags = 1; // ExtensionPoint disable
            Native.SetProcessMitigationPolicy(
                Native.PROCESS_MITIGATION_POLICY.ExtensionPointDisablePolicy, ref flags, (IntPtr)4);
        }
        catch { /* best effort */ }

        if (antiDebugger && DebuggerAttached())
            Environment.Exit(0x1D);
    }

    public static bool DebuggerAttached()
    {
        try
        {
            if (Native.IsDebuggerPresent()) return true;
            bool remote = false;
            Native.CheckRemoteDebuggerPresent(Native.GetCurrentProcess(), ref remote);
            if (remote) return true;
            if (System.Diagnostics.Debugger.IsAttached) return true;
        }
        catch { }
        return false;
    }
}
