using System.IO;
using System.Text.Json.Serialization;

namespace VaultType.Config;

// Which kind of server an account lives on. Vaultwarden is self-hosted (editable URL); the two
// Bitwarden clouds have fixed region URLs. Stored as text so the config stays readable.
public enum AccountKind { Vaultwarden, BitwardenUS, BitwardenEU }

// One vault account. Non-secret only: a display name, a badge colour, the server and the last
// email we used. Each account keeps its own bw.exe session store and icon cache under its own
// directory, so several accounts stay fully isolated from one another.
public sealed class AccountConfig
{
    // stable id, also used as the on-disk folder name (hex, filesystem-safe)
    public string Id { get; set; } = "";

    // what the user calls this account ("Private", "Work"); shown as the picker badge
    public string Name { get; set; } = "";

    // badge colour, "#RRGGBB"
    public string ColorHex { get; set; } = DefaultColor;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public AccountKind Kind { get; set; } = AccountKind.Vaultwarden;

    // the effective server URL (self-hosted address, or the fixed cloud region URL)
    public string ServerUrl { get; set; } = "";

    // last email used - just prefills the sign-in dialog, not a secret
    public string AccountEmail { get; set; } = "";

    // set once this account has signed in successfully
    public bool SignedInBefore { get; set; }

    // preferred unlock method for this vault: password | pin | bio | passkey (design "Künftig
    // entsperren mit"). Methods without a working envelope fall back to the master password.
    public string UnlockMethod { get; set; } = "password";

    // with PIN unlock: require the master password once after a restart (RAM-only envelope)
    public bool PinRequireMasterOnRestart { get; set; } = true;

    // when this account last completed a successful sync (login, unlock and manual sync all
    // sync); feeds the tray menu's "last synced" hint across restarts
    public DateTimeOffset? LastSyncUtc { get; set; }

    // when this account was last unlocked. With several vaults configured, the one used most
    // recently is what the picker offers to unlock first - that is almost always the one wanted
    // again, rather than whichever happens to sit first in the list.
    public DateTimeOffset? LastUnlockedUtc { get; set; }

    public const string UsCloud = "https://vault.bitwarden.com";
    public const string EuCloud = "https://vault.bitwarden.eu";

    // distinct, readable avatar/badge base colours (the design palette's light gradient stops);
    // avatars render as a gradient from this colour to a darker shade. New accounts cycle through.
    public static readonly string[] Palette =
    {
        "#8AA64A", "#3D7FC0", "#A371F7", "#1ABC9C",
        "#E5486F", "#E08E0B", "#6B7BFF",
    };
    public const string DefaultColor = "#8AA64A";

    [JsonIgnore] public string DataDir => Path.Combine(AppConfig.AccountsDir, Id);
    [JsonIgnore] public string BwDataDir => Path.Combine(DataDir, "bw-data");
    [JsonIgnore] public string IconCacheDir => Path.Combine(DataDir, "icons");
    // non-secret public SSH-key metadata, so the agent can advertise keys while this vault is locked
    [JsonIgnore] public string SshMetaPath => Path.Combine(DataDir, "ssh-public.json");
    // non-secret passkey metadata, so the Windows picker can list passkeys while this vault is locked
    [JsonIgnore] public string PasskeyMetaPath => Path.Combine(DataDir, "passkey-meta.json");

    public static AccountKind KindFromServer(string server)
        => string.Equals(server, UsCloud, StringComparison.OrdinalIgnoreCase) ? AccountKind.BitwardenUS
         : string.Equals(server, EuCloud, StringComparison.OrdinalIgnoreCase) ? AccountKind.BitwardenEU
         : AccountKind.Vaultwarden;

    // a fresh account with a stable id and the next unused palette colour
    public static AccountConfig CreateNew(IReadOnlyList<AccountConfig> existing)
        => new()
        {
            Id = Guid.NewGuid().ToString("N"),
            ColorHex = Palette[existing.Count % Palette.Length],
        };

    // a readable fallback name: the email local-part, else the server host, else "Account"
    public string DeriveName()
    {
        if (!string.IsNullOrWhiteSpace(AccountEmail))
        {
            int at = AccountEmail.IndexOf('@');
            return at > 0 ? AccountEmail[..at] : AccountEmail;
        }
        string host = HostOf(ServerUrl);
        return host.Length > 0 ? host : "Account";
    }

    private static string HostOf(string url)
    {
        string rest = url;
        int scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) rest = rest[(scheme + 3)..];
        int slash = rest.IndexOfAny(new[] { '/', '?', '#' });
        if (slash >= 0) rest = rest[..slash];
        int colon = rest.IndexOf(':');
        if (colon >= 0) rest = rest[..colon];
        return rest;
    }
}
