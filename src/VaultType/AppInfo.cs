using System.Reflection;
using System.Runtime.InteropServices;

namespace VaultType;

// App version, read from the assembly (the build stamps it via -p:Version).
public static class AppInfo
{
    // Deep link to VaultType's Microsoft Store product page (Partner Center "Product identity").
    public const string StoreUri = "ms-windows-store://pdp/?productid=9N5CLMW5XJ49";

    // True when the process runs from an MSIX package (has a package identity), i.e. the Store or
    // a dev-signed MSIX install. Packaged builds get their updates from the Store, and only they
    // can be activated as a passkey plugin.
    public static bool IsPackaged
    {
        get
        {
            try
            {
                int len = 0;
                int rc = GetCurrentPackageFullName(ref len, null);
                return rc != 15700;   // APPMODEL_ERROR_NO_PACKAGE
            }
            catch { return false; }
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref int packageFullNameLength, char[]? packageFullName);

    public static string Version
    {
        get
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "1.0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
        }
    }
}
