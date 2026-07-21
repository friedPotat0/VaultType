using Microsoft.Win32;

namespace VaultType.Services;

// "Start with Windows" toggle, backed by the per-user Run key.
public static class AutostartService
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "VaultType";

    public static void Set(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (key == null) return;
            if (enabled)
                key.SetValue(ValueName, $"\"{Environment.ProcessPath}\"");
            else
                key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
        catch (Exception ex)
        {
            // e.g. locked-down Run key / registry permissions. Don't crash the app over autostart,
            // but leave a trace so a silent "Start with Windows" failure is diagnosable.
            System.Diagnostics.Debug.WriteLine($"AutostartService.Set failed: {ex.Message}");
        }
    }
}
