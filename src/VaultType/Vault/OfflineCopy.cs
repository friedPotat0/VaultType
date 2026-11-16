using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace VaultType.Vault;

// The on-disk offline copy of one account's vault. Three layers stand between the file and the
// vault's contents:
//   1. The payload is the raw /api/sync body sealed with the account's user key (AES-256-CBC +
//      HMAC-SHA256 EncString). Every cipher inside it is additionally still encrypted exactly as
//      the server stores it. The user key itself only opens with the master password (through
//      the account's KDF) or the PIN envelope, neither of which is in this file.
//   2. The whole document is sealed with DPAPI (current Windows user), so a copied file is
//      useless on another machine or under another account.
//   3. The file's ACL grants access to the current user only, and it carries the read-only
//      attribute. VaultType never writes it back to the server; it is replaced after every
//      successful sync, so the online vault always remains the source of truth.
public static class OfflineCopy
{
    private static readonly byte[] Magic = "VTOFFLINE1\n"u8.ToArray();
    private static readonly byte[] Entropy = "VaultType.OfflineCopy.v1"u8.ToArray();

    public sealed class Document
    {
        public string AccountId { get; set; } = "";
        public DateTimeOffset SavedUtc { get; set; }
        public string Payload { get; set; } = "";   // EncString(userKey, raw sync JSON)
    }

    public static string PathFor(string folder, string accountId, string accountDataDir)
        => Path.Combine(string.IsNullOrWhiteSpace(folder) ? accountDataDir : folder, $"VaultType-{accountId}.offline");

    public static void Write(string path, Document doc)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(doc);
        byte[] sealed_;
        try { sealed_ = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(json); }

        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        DeleteFile(tmp);

        // Owner-only ACL from the moment the file exists; a rename on the same volume keeps it.
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.FullControl, AccessControlType.Allow));
        using (var fs = new FileInfo(tmp).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                   FileShare.None, 4096, FileOptions.WriteThrough, security))
        {
            fs.Write(Magic);
            fs.Write(sealed_);
        }

        if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
        File.Move(tmp, path, overwrite: true);
        File.SetAttributes(path, FileAttributes.ReadOnly);
    }

    // Null when there is no copy, it belongs to another account, or it can't be opened here.
    public static Document? Read(string path, string accountId)
    {
        try
        {
            if (!File.Exists(path)) return null;
            byte[] data = File.ReadAllBytes(path);
            if (data.Length <= Magic.Length || !data.AsSpan(0, Magic.Length).SequenceEqual(Magic)) return null;
            byte[] json = ProtectedData.Unprotect(data[Magic.Length..], Entropy, DataProtectionScope.CurrentUser);
            try
            {
                var doc = JsonSerializer.Deserialize<Document>(json);
                return doc != null && doc.AccountId == accountId && doc.Payload.Length > 0 ? doc : null;
            }
            finally { CryptographicOperations.ZeroMemory(json); }
        }
        catch { return null; }
    }

    public static void Delete(string path)
    {
        DeleteFile(path);
        DeleteFile(path + ".tmp");
    }

    private static void DeleteFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch { }
    }
}
