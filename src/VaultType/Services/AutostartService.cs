using Microsoft.Win32;

namespace VaultType.Services;

// "Start with Windows" toggle, backed by the per-user Run key. The Store edition can't use that key
// (a packaged app's registry writes stay inside its package), so it declares a startup task in its
// manifest instead, which Windows Settings > Apps > Startup controls.
public static class AutostartService
{
    public const string WindowsStartupSettings = "ms-settings:startupapps";

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "VaultType";

    public static void Set(bool enabled)
    {
        if (AppInfo.IsPackaged) return;
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (key == null) return;
            if (enabled)
                key.SetValue(ValueName, $"\"{Environment.ProcessPath}\"");
            else
                key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
        catch
        {
            // e.g. locked-down Run key / registry permissions. Don't crash the app over autostart.
        }
    }
}
