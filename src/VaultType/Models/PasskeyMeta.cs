using System.IO;
using System.Text.Json;

namespace VaultType.Models;

// Non-secret metadata for one passkey (credential id, RP, user names). Persisted per account -
// mirroring SshKeyMeta - so the Windows passkey picker can still list a locked vault's passkeys;
// picking one pops the unlock window, and only then is the private key available for signing.
// Contains no secret material.
public sealed class PasskeyMeta
{
    public string CredentialId { get; set; } = "";   // b64 of the wire-format id
    public string RpId { get; set; } = "";
    public string RpName { get; set; } = "";
    public string UserHandle { get; set; } = "";     // b64
    public string UserName { get; set; } = "";
    public string UserDisplayName { get; set; } = "";
    public string ItemName { get; set; } = "";
    public bool Discoverable { get; set; }

    public static PasskeyMeta From(Fido2Entry e) => new()
    {
        CredentialId = Convert.ToBase64String(e.CredentialId),
        RpId = e.RpId,
        RpName = e.RpName,
        UserHandle = e.UserHandle.Length > 0 ? Convert.ToBase64String(e.UserHandle) : "",
        UserName = e.UserName,
        UserDisplayName = e.UserDisplayName,
        ItemName = e.ItemName,
        Discoverable = e.Discoverable,
    };

    // Metadata-only view for announcing to Windows; never carries a private key.
    public Fido2Entry ToEntry() => new()
    {
        CredentialId = CredentialId.Length > 0 ? Convert.FromBase64String(CredentialId) : Array.Empty<byte>(),
        RpId = RpId,
        RpName = RpName,
        UserHandle = UserHandle.Length > 0 ? Convert.FromBase64String(UserHandle) : Array.Empty<byte>(),
        UserName = UserName,
        UserDisplayName = UserDisplayName,
        ItemName = ItemName,
        Discoverable = Discoverable,
    };

    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    public static void Save(string path, IEnumerable<PasskeyMeta> entries)
    {
        try
        {
            var list = entries.ToList();
            if (list.Count == 0) { Delete(path); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(list, Opts));
        }
        catch { /* metadata is a convenience cache; failing to write it is non-fatal */ }
    }

    public static List<PasskeyMeta> Load(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<List<PasskeyMeta>>(File.ReadAllText(path)) ?? new()
                : new();
        }
        catch { return new(); }
    }

    public static void Delete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
