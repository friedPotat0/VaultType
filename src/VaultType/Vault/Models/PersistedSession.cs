using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultType.Vault.Models;

// What we persist per account so the vault survives a restart without re-login: the KDF params, the
// protected (master-key-wrapped) user key, the protected RSA key, and the refresh token. None of
// this is usable without the master password (or a configured PIN/biometric envelope): the user key
// only decrypts once the master key derived from the password unwraps it. The refresh token is the
// one genuinely sensitive value at rest, so it is additionally sealed with Windows DPAPI (per user).
public sealed class PersistedSession
{
    public int Kdf { get; set; }
    public int KdfIterations { get; set; } = 600_000;
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }

    public string? ProtectedUserKey { get; set; }   // token/profile "Key" (EncString type 2)
    public string? ProtectedPrivateKey { get; set; } // "PrivateKey" (EncString type 2)
    public string? Email { get; set; }
    public string? ServerUrl { get; set; }
    public string? DeviceIdentifier { get; set; }

    // DPAPI-sealed refresh token (base64 of the protected blob). Never the plaintext token.
    public string? ProtectedRefreshToken { get; set; }

    // Optional PIN unlock envelope: the user key wrapped by a PIN-derived key (EncString type 2).
    // With "require master password on restart" this stays empty on disk (RAM only).
    public string? PinProtectedUserKey { get; set; }
    public bool PinRequiresMasterPasswordOnRestart { get; set; }

    // The PIN itself, wrapped by the user key (EncString type 2). Lets a master-password unlock
    // rebuild the RAM-only PIN envelope after a restart (Bitwarden's protectedPin).
    public string? ProtectedPin { get; set; }

    // Consecutive failed PIN unlock attempts. Persisted so a restart can't reset the counter; when
    // it reaches the limit the PIN envelope is dropped and the master password is required again.
    public int PinFailedAttempts { get; set; }

    [JsonIgnore]
    public string? RefreshToken
    {
        get => Unprotect(ProtectedRefreshToken);
        set => ProtectedRefreshToken = Protect(value);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string json = JsonSerializer.Serialize(this, JsonOpts);
        // Write to a temp file in the same directory, then swap it into place so a crash mid-write
        // cannot corrupt an existing, intact session and force an unnecessary re-login.
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        if (File.Exists(path))
            File.Replace(tmp, path, null);
        else
            File.Move(tmp, path, overwrite: true);
    }

    public static PersistedSession? Load(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<PersistedSession>(File.ReadAllText(path)) : null; }
        catch { return null; }
    }

    public static void Delete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static string? Protect(string? plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return null;
        byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            byte[] sealed_ = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(sealed_);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string? Unprotect(string? protectedB64)
    {
        if (string.IsNullOrEmpty(protectedB64)) return null;
        try
        {
            byte[] plain = ProtectedData.Unprotect(Convert.FromBase64String(protectedB64), null, DataProtectionScope.CurrentUser);
            try { return Encoding.UTF8.GetString(plain); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch { return null; }
    }
}
