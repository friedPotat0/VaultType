using VaultType.Config;
using VaultType.Models;
using VaultType.Security;
using VaultType.Vault;

namespace VaultType.Services;

// Everything tied to one account at runtime: its native vault backend (login/unlock/sync/crypto,
// pointed at the account's own data dir), its icon service and - once unlocked - the decrypted
// items and the ephemeral secret protector (both owned by the backend). Every account has its own
// backend, so keys and secrets never mix between vaults.
public sealed class VaultSession
{
    public AccountConfig Cfg { get; }
    public VaultBackend Backend { get; }
    public IconService Icons { get; private set; }

    public VaultSession(AccountConfig cfg, AppConfig app)
    {
        Cfg = cfg;
        Backend = new VaultBackend(app, cfg);
        Icons = new IconService(cfg.ServerUrl, app.ShowIcons, cfg.IconCacheDir);
    }

    // Decrypted items and the protector live on the backend; expose them for the rest of the app.
    public List<VaultItem> Items => Backend.Items;
    public List<SshKeyEntry> SshKeys => Backend.SshKeys;
    public SecretProtector? Protector => Backend.Protector;
    public bool Unlocked => Backend.Unlocked;

    // Rebuild the icon service once the account's server is known (e.g. after a fresh sign-in),
    // so favicons can be fetched from it instead of falling back to letter avatars.
    public void RebuildIcons(AppConfig app)
    {
        var previous = Icons;
        Icons = new IconService(Cfg.ServerUrl, app.ShowIcons, Cfg.IconCacheDir);
        previous.Dispose();   // release the old instance's HttpClient instead of leaking it
    }

    // Drop the in-RAM session: wipe keys, forget items. The account stays configured and its
    // persisted refresh token is kept so it can be unlocked again without a full sign-in.
    public void Lock() => Backend.Lock();
}
