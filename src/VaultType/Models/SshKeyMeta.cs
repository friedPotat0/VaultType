using System.IO;
using System.Text.Json;

namespace VaultType.Models;

// Non-secret public metadata for one SSH key (id, comment, type, fingerprint, public key line).
// Persisted per account so the SSH agent can still advertise a vault's keys while it is locked -
// the private key is only revealed after an unlock. Contains no secret material.
public sealed class SshKeyMeta
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string PublicKey { get; set; } = "";

    public static SshKeyMeta From(SshKeyEntry k) => new()
    {
        Id = k.Id, Name = k.Name, Type = k.Type, Fingerprint = k.Fingerprint, PublicKey = k.PublicKey,
    };

    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    // Save (or clear) the public key list next to the account's session store.
    public static void Save(string path, IEnumerable<SshKeyMeta> keys)
    {
        try
        {
            var list = keys.ToList();
            if (list.Count == 0) { Delete(path); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(list, Opts));
        }
        catch { /* metadata is a convenience cache; failing to write it is non-fatal */ }
    }

    public static List<SshKeyMeta> Load(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<List<SshKeyMeta>>(File.ReadAllText(path)) ?? new()
                : new();
        }
        catch { return new(); }
    }

    public static void Delete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
