using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultType.Config;

// Non-secret settings only - no passwords, session keys or vault contents in here, just
// behaviour and addresses. Lives at %LOCALAPPDATA%\VaultType\config.json.
public sealed class AppConfig
{
    // the configured vault accounts (one or more servers/logins). Empty on a fresh install.
    public List<AccountConfig> Accounts { get; set; } = new();

    // global hotkey, e.g. "Ctrl+Alt+A"
    public string Hotkey { get; set; } = "Ctrl+Alt+A";

    // auto-lock after this many idle minutes (0 = never)
    public int IdleTimeoutMinutes { get; set; } = 30;

    // Delay between simulated keystrokes, in ms. Not as low as it could be: apps that decode the
    // injected VK_PACKET events asynchronously (the Windows 11 Notepad, Electron apps) garble the
    // text below roughly 15 ms - characters come out repeated or swapped, because they resolve a
    // queued event against a keyboard state that has already moved on.
    public int TypingDelayMs { get; set; } = 25;

    // select each field (Ctrl+A) before typing so we overwrite whatever was prefilled
    public bool ClearFieldBeforeTyping { get; set; } = true;

    // When filling a form from a card or identity, restrict it to the fields the form marks as
    // mandatory. Off means every field VaultType recognises gets filled. Forms that mark nothing at
    // all are filled completely either way - otherwise nothing would happen on them.
    public bool FillRequiredFieldsOnly { get; set; } = true;

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

    // Extra spellings for the {FIELD ...} lookup, keyed by field group (e.g. "CardCode":
    // ["kartenprüfwert"]). Merged on top of the builtin lists so an unusual form can be taught
    // without waiting for a new release.
    public Dictionary<string, List<string>> FieldAliases { get; set; } = new();

    // URI match rule for entries that don't set their own (0 = base domain, 1 = host).
    // Bitwarden's own default is base domain; host is handy when every service sits on its
    // own subdomain of one domain.
    public int DefaultUriMatch { get; set; } = 0;

    // keep windows out of screenshots / screen scrapers
    public bool ExcludeFromScreenCapture { get; set; } = true;

    // bail out if a debugger attaches (anti memory-scraping)
    public bool AntiDebugger { get; set; } = true;

    // honour the master-password reprompt flag on entries that ask for it
    public bool HonorMasterPasswordReprompt { get; set; } = true;

    // what a left click on the tray icon does: 0 = open the menu, 1 = start auto-type,
    // 2 = open the settings (design "Tray-Klick"; default)
    public int TrayClickAction { get; set; } = 2;

    // the "VaultType is running" balloon is shown once after installation, not on every start
    public bool FirstRunNotified { get; set; }

    // ---- updates ----

    // Look for a new release on GitHub in the background (at most once a day). Off by default:
    // without it the app never contacts anything but your own vault server on its own.
    // Deliberately NOT named AutoUpdateCheck: configs written before 1.2.0 still carry that key
    // with `true` (it was a setting that never did anything), and reusing the name would switch
    // background requests on for those users without them ever asking for it.
    public bool BackgroundUpdateCheck { get; set; }

    // when the background check last reached GitHub, so restarts don't re-ask every time
    public DateTimeOffset? LastUpdateCheckUtc { get; set; }

    // The newer release the last check found, remembered so the tray indicator survives a restart
    // without another request. Cleared once the running version has caught up.
    public string? KnownUpdateVersion { get; set; }
    public string? KnownUpdateUrl { get; set; }

    // ---- integration (design "Integration" section) ----

    // serve vault SSH keys over the Windows OpenSSH agent named pipe
    public bool SshAgentEnabled { get; set; }

    // ask before every SSH signature request
    public bool SshConfirmEachUse { get; set; } = true;

    // register VaultType as a Windows 11 passkey provider (not functional yet - see docs)
    public bool PasskeyProviderEnabled { get; set; }

    // gate passkey use behind Windows Hello
    public bool PasskeyRequireHello { get; set; } = true;

    // cipher ids of SSH keys the user switched OFF in the agent (default: every key is served)
    public List<string> SshDisabledKeys { get; set; } = new();

    [JsonIgnore]
    public static string DataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VaultType");

    // one sub-folder per account (its bw.exe session store + icon cache)
    [JsonIgnore]
    public static string AccountsDir { get; } = Path.Combine(DataDir, "accounts");

    [JsonIgnore]
    public static string ConfigPath { get; } = Path.Combine(DataDir, "config.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // Serialises config.json access so overlapping writes (idle-timer + settings window) never
    // interleave. Monitor is reentrant, so Load -> Migrate -> Save on one thread is safe.
    private static readonly object FileGate = new();

    public static AppConfig Load()
    {
        lock (FileGate)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                Directory.CreateDirectory(AccountsDir);
                RestrictAcl(DataDir);
                if (File.Exists(ConfigPath))
                {
                    var json = File.ReadAllText(ConfigPath);
                    var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
                    if (cfg != null)
                    {
                        if (cfg.Accounts.Count == 0) Migrate(cfg, json);
                        foreach (var a in cfg.Accounts) { try { Directory.CreateDirectory(a.BwDataDir); } catch { } }
                        return cfg;
                    }
                }
            }
            catch { /* fall back to defaults */ }
            return new AppConfig();
        }
    }

    // Pre-multi-account configs kept a single account in top-level ServerUrl/AccountEmail/
    // SignedInBefore fields and a single global bw-data folder. Fold that into one AccountConfig
    // and move the CLI's session store into the new per-account folder, so existing users stay
    // signed in without touching their vault.
    private static void Migrate(AppConfig cfg, string json)
    {
        try
        {
            var legacy = JsonSerializer.Deserialize<LegacyConfig>(json, JsonOpts);
            if (legacy == null) return;
            if (!legacy.SignedInBefore && legacy.ServerUrl.Length == 0 && legacy.AccountEmail.Length == 0) return;

            var acc = AccountConfig.CreateNew(cfg.Accounts);
            acc.ServerUrl = legacy.ServerUrl;
            acc.AccountEmail = legacy.AccountEmail;
            acc.SignedInBefore = legacy.SignedInBefore;
            acc.Kind = AccountConfig.KindFromServer(legacy.ServerUrl);
            acc.Name = acc.DeriveName();
            cfg.Accounts.Add(acc);

            string oldBwData = Path.Combine(DataDir, "bw-data");
            string oldIcons = Path.Combine(DataDir, "icons");
            try { Directory.CreateDirectory(acc.DataDir); } catch { }
            try { if (Directory.Exists(oldBwData) && !Directory.Exists(acc.BwDataDir)) Directory.Move(oldBwData, acc.BwDataDir); } catch { }
            try { if (Directory.Exists(oldIcons) && !Directory.Exists(acc.IconCacheDir)) Directory.Move(oldIcons, acc.IconCacheDir); } catch { }

            cfg.Save();
        }
        catch { /* leave the config as-is; the user just signs in again */ }
    }

    // Just the fields an old config.json carried for its single account.
    private sealed class LegacyConfig
    {
        public string ServerUrl { get; set; } = "";
        public string AccountEmail { get; set; } = "";
        public bool SignedInBefore { get; set; }
    }

    public void Save()
    {
        lock (FileGate)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                string json = JsonSerializer.Serialize(this, JsonOpts);
                // Write to a temp file in the same directory, then swap it into place, so a crash
                // mid-write can never leave a half-written (and thus unreadable) config.json that
                // would make Load() fall back to defaults and drop every configured account.
                string tmp = ConfigPath + ".tmp";
                File.WriteAllText(tmp, json);
                if (File.Exists(ConfigPath))
                    File.Replace(tmp, ConfigPath, null);
                else
                    File.Move(tmp, ConfigPath, overwrite: true);
            }
            catch { /* not critical */ }
        }
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
