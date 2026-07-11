using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultType.Config;

// Non-secret settings only - no passwords, session keys or vault contents in here, just
// behaviour and addresses. Lives at %LOCALAPPDATA%\VaultType\config.json.
public sealed class AppConfig
{
    // your (self-hosted) Vaultwarden/Bitwarden server URL
    public string ServerUrl { get; set; } = "";

    // last account email we used - just prefills the sign-in dialog, not a secret
    public string AccountEmail { get; set; } = "";

    // global hotkey, e.g. "Ctrl+Alt+A"
    public string Hotkey { get; set; } = "Ctrl+Alt+A";

    // auto-lock after this many idle minutes (0 = never)
    public int IdleTimeoutMinutes { get; set; } = 30;

    // delay between simulated keystrokes, in ms
    public int TypingDelayMs { get; set; } = 4;

    // select each field (Ctrl+A) before typing so we overwrite whatever was prefilled
    public bool ClearFieldBeforeTyping { get; set; } = true;

    // real favicons from your own Vaultwarden (/icons); off = letter avatars, fully offline
    public bool ShowIcons { get; set; } = true;

    // wipe the clipboard this many seconds after a copy (0 = never)
    public int ClipboardClearSeconds { get; set; } = 12;

    // let a tray-icon click open the picker (needs a lightweight foreground hook); off = hotkey only
    public bool EnableTrayClick { get; set; } = true;

    // start with Windows (adds a per-user Run entry); on by default
    public bool Autostart { get; set; } = true;

    // UI language: "auto" (follow Windows) or a code like "de", "fr", "zh_CN"
    public string Language { get; set; } = "auto";

    // name of the custom entry field that holds a per-entry auto-type sequence
    public string AutoTypeFieldName { get; set; } = "auto-type";

    // keep windows out of screenshots / screen scrapers
    public bool ExcludeFromScreenCapture { get; set; } = true;

    // bail out if a debugger attaches (anti memory-scraping)
    public bool AntiDebugger { get; set; } = true;

    // honour the master-password reprompt flag on entries that ask for it
    public bool HonorMasterPasswordReprompt { get; set; } = true;

    // set once the user has signed in successfully; lets first run go straight to the sign-in form
    public bool SignedInBefore { get; set; } = false;

    [JsonIgnore]
    public static string DataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VaultType");

    [JsonIgnore]
    public static string BwDataDir { get; } = Path.Combine(DataDir, "bw-data");

    [JsonIgnore]
    public static string ConfigPath { get; } = Path.Combine(DataDir, "config.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static AppConfig Load()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            Directory.CreateDirectory(BwDataDir);
            RestrictAcl(DataDir);
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
                if (cfg != null) return cfg;
            }
        }
        catch { /* fall back to defaults */ }
        return new AppConfig();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch { /* not critical */ }
    }

    // lock the data dir down to the current user and kill ACL inheritance
    private static void RestrictAcl(string dir)
    {
        try
        {
            var di = new DirectoryInfo(dir);
            var sec = di.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                me,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
            di.SetAccessControl(sec);
        }
        catch { /* best effort */ }
    }
}
