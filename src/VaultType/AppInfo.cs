using System.Reflection;

namespace VaultType;

// App version, read from the assembly (the build stamps it via -p:Version).
public static class AppInfo
{
    public static string Version
    {
        get
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "1.0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
        }
    }
}
