using System.Security.Cryptography;
using System.Text;
using VaultType.Models;
using VaultType.Security;
using VaultType.Vault.Crypto;
using VaultType.Vault.Models;

namespace VaultType.Vault;

// Dev-only end-to-end check against a real server (--vaulttest). Runs the full login + sync +
// decrypt pipeline and reports non-secret results (item names, counts) so the protocol/crypto
// wiring can be verified against Vaultwarden and Bitwarden without a debugger.
public static class VaultLiveTest
{
    public static async Task<string> RunAsync(string server, string email, string password,
        string? twoFactorCode, int? twoFactorProvider, string? newDeviceOtp)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"VaultType live test  server={server}  email={email}");
        var deviceId = Guid.NewGuid().ToString();
        using var api = new VaultApiClient(server, deviceId);

        // 1) prelogin
        var pre = await api.PreloginAsync(email);
        var kdf = pre.Kdf == 1
            ? KdfConfig.Argon2(pre.KdfIterations, pre.KdfMemory ?? 64, pre.KdfParallelism ?? 4)
            : KdfConfig.Pbkdf2(pre.KdfIterations);
        sb.AppendLine($"  prelogin: kdf={(pre.Kdf == 1 ? "Argon2id" : "PBKDF2")} iters={pre.KdfIterations} mem={pre.KdfMemory} par={pre.KdfParallelism}");

        // 2) derive master key + auth hash
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] masterKey = Kdf.DeriveMasterKey(email, pw, kdf);
        string authHash = Kdf.MasterPasswordAuthHash(masterKey, pw);
        CryptographicOperations.ZeroMemory(pw);

        // 3) token
        var (token, raw, ok) = await api.TokenPasswordAsync(email, authHash, twoFactorCode, twoFactorProvider, false, newDeviceOtp);
        if (!ok)
        {
            if (token.Requires2Fa)
            {
                sb.AppendLine($"  token: 2FA REQUIRED. providers={token.TwoFactorProviders2}");
                return sb.ToString();
            }
            sb.AppendLine($"  token FAILED: error={token.Error} desc={token.ErrorDescription}");
            sb.AppendLine($"  raw: {(raw.Length > 400 ? raw[..400] : raw)}");
            return sb.ToString();
        }
        sb.AppendLine($"  token OK: expires_in={token.ExpiresIn} hasKey={token.Key != null} hasPrivateKey={token.PrivateKey != null} refresh={token.RefreshToken != null}");

        // 4) sync
        var (sync, _) = await api.SyncAsync(token.AccessToken!);
        var profile = sync.Profile;
        sb.AppendLine($"  sync: ciphers={sync.Ciphers.Count} folders={sync.Folders.Count} orgs={profile?.Organizations.Count ?? 0}");

        // 5) unlock crypto (prefer the profile key/privateKey; fall back to token's)
        using var crypto = new AccountCrypto();
        string userKeyEnc = profile?.Key ?? token.Key ?? throw new InvalidOperationException("No protected user key.");
        string? privKeyEnc = profile?.PrivateKey ?? token.PrivateKey;
        crypto.Unlock(masterKey, userKeyEnc, privKeyEnc, profile?.Organizations ?? new());
        CryptographicOperations.ZeroMemory(masterKey);
        sb.AppendLine("  unlock: user key + RSA key unwrapped OK");

        // 6) decrypt
        using var protector = new SecretProtector();
        int logins = 0, withTotp = 0, sshKeys = 0, passkeys = 0, otherTypes = 0, failed = 0;
        var names = new List<string>();
        foreach (var c in sync.Ciphers)
        {
            try
            {
                if (c.Type == 1)
                {
                    var it = crypto.DecryptLogin(c, protector, "auto-type");
                    if (it != null)
                    {
                        logins++;
                        if (it.HasTotp) withTotp++;
                        if (c.Login?.Fido2Credentials.Count > 0) passkeys += c.Login.Fido2Credentials.Count;
                        if (names.Count < 25) names.Add(it.Name + (it.Uris.Count > 0 ? $"  [{it.Uris[0].Host}]" : ""));
                    }
                }
                else if (c.Type == 5) sshKeys++;
                else otherTypes++;
            }
            catch (Exception ex) { failed++; if (failed <= 3) sb.AppendLine($"    decrypt error: {ex.Message}"); }
        }
        sb.AppendLine($"  decrypted: logins={logins} withTotp={withTotp} sshKeys={sshKeys} passkeys={passkeys} otherTypes={otherTypes} failed={failed}");
        sb.AppendLine("  --- item names (max 25) ---");
        foreach (var n in names) sb.AppendLine($"    {n}");
        sb.AppendLine("  RESULT: " + (failed == 0 ? "OK" : $"{failed} decrypt failures"));
        return sb.ToString();
    }

    // Create -> sync -> decrypt -> compare -> add-uri -> delete round-trip. Verifies the encrypt AND
    // decrypt paths (incl. the AddUri edit) end-to-end through a real server. Cleans up after itself.
    public static async Task<string> RunWriteTestAsync(string server, string email, string password)
    {
        var sb = new StringBuilder();
        int pass = 0, fail = 0;
        void Check(string n, bool ok, string? d = null) { if (ok) { pass++; sb.AppendLine($"  PASS  {n}"); } else { fail++; sb.AppendLine($"  FAIL  {n}{(d != null ? " -- " + d : "")}"); } }

        using var api = new VaultApiClient(server, Guid.NewGuid().ToString());
        var pre = await api.PreloginAsync(email);
        var kdf = pre.Kdf == 1 ? KdfConfig.Argon2(pre.KdfIterations, pre.KdfMemory ?? 64, pre.KdfParallelism ?? 4) : KdfConfig.Pbkdf2(pre.KdfIterations);
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] masterKey = Kdf.DeriveMasterKey(email, pw, kdf);
        string authHash = Kdf.MasterPasswordAuthHash(masterKey, pw);
        CryptographicOperations.ZeroMemory(pw);
        var (token, raw, ok) = await api.TokenPasswordAsync(email, authHash, null, null, false, null);
        if (!ok) { sb.AppendLine($"  token FAILED: {token.Error} {token.ErrorDescription}"); return sb.ToString(); }
        string access = token.AccessToken!;

        var (sync0, _) = await api.SyncAsync(access);
        using var crypto = new AccountCrypto();
        crypto.Unlock(masterKey, sync0.Profile?.Key ?? token.Key!, sync0.Profile?.PrivateKey ?? token.PrivateKey, sync0.Profile?.Organizations ?? new());
        CryptographicOperations.ZeroMemory(masterKey);

        const string name = "VaultType RoundTrip ✓";
        const string user = "rt-user@example.com";
        const string secret = "P@ss-röundtrip-🔑-123";
        const string totpSeed = "JBSWY3DPEHPK3PXP";
        const string uri1 = "https://roundtrip.example.com";
        const string uri2 = "https://second.example.com";

        string createBody = CipherJson.BuildCreateLogin(
            crypto.EncryptWithUserKey(name), crypto.EncryptWithUserKey(user),
            crypto.EncryptWithUserKey(secret), crypto.EncryptWithUserKey(totpSeed),
            new[] { crypto.EncryptWithUserKey(uri1) });
        string createResp = await api.PostCipherAsync(access, createBody);
        string? newId = System.Text.Json.JsonDocument.Parse(createResp).RootElement.TryGetProperty("id", out var idEl) ? idEl.GetString()
                       : System.Text.Json.JsonDocument.Parse(createResp).RootElement.TryGetProperty("Id", out var idEl2) ? idEl2.GetString() : null;
        Check("create returned id", newId != null, createResp.Length > 200 ? createResp[..200] : createResp);
        if (newId == null) return sb.ToString();

        try
        {
            // re-sync, find, decrypt, compare
            var (sync1, _) = await api.SyncAsync(access);
            var c = sync1.Ciphers.FirstOrDefault(x => x.Id == newId);
            Check("item present after sync", c != null);
            if (c == null) return sb.ToString();

            using var protector = new SecretProtector();
            var it = crypto.DecryptLogin(c, protector, "auto-type")!;
            Check("name round-trips", it.Name == name, it.Name);
            Check("username round-trips", it.Username == user, it.Username);
            Check("uri round-trips", it.Uris.Count == 1 && it.Uris[0].Value == uri1, it.Uris.Count > 0 ? it.Uris[0].Value : "(none)");
            Check("password round-trips", Reveal(protector, it.Password) == secret);
            string tSeed = Reveal(protector, it.TotpSecret);
            Check("totp seed round-trips", tSeed == totpSeed, tSeed);
            string? code = Services.Totp.Compute(tSeed);
            Check("totp code generated", code is { Length: 6 }, code);
            sb.AppendLine($"    (current TOTP code: {code})");

            // add-uri edit
            string putBody = CipherJson.BuildAddUriBody(c, crypto.EncryptWithUserKey(uri2));
            await api.PutCipherAsync(access, newId, putBody);
            var (sync2, _) = await api.SyncAsync(access);
            var c2 = sync2.Ciphers.First(x => x.Id == newId);
            var it2 = crypto.DecryptLogin(c2, protector, "auto-type")!;
            Check("add-uri produced 2 uris", it2.Uris.Count == 2, string.Join(", ", it2.Uris.Select(u => u.Value)));
            Check("original uri preserved", it2.Uris.Any(u => u.Value == uri1));
            Check("new uri added", it2.Uris.Any(u => u.Value == uri2));
        }
        finally
        {
            try { await api.DeleteCipherAsync(access, newId); sb.AppendLine("  cleanup: test item deleted"); }
            catch (Exception ex) { sb.AppendLine($"  cleanup FAILED (delete {newId}): {ex.Message}"); }
        }

        sb.Insert(0, $"VaultType write round-trip: {pass} passed, {fail} failed\n");
        return sb.ToString();
    }

    private static string Reveal(SecretProtector p, SecretBox? box)
    {
        if (box == null) return "(null)";
        using var lb = p.Reveal(box);
        return Encoding.UTF8.GetString(lb.Span.Slice(0, box.Cipher.Length));
    }

    // Exercises the VaultBackend facade: sign in -> persist -> lock -> unlock-from-state -> logout.
    // The unlock step proves the refresh-token + stored-key persistence works (no re-login needed).
    public static async Task<string> RunBackendTestAsync(string server, string email, string password)
    {
        var sb = new StringBuilder();
        int pass = 0, fail = 0;
        void Check(string n, bool ok, string? d = null) { if (ok) { pass++; sb.AppendLine($"  PASS  {n}"); } else { fail++; sb.AppendLine($"  FAIL  {n}{(d != null ? " -- " + d : "")}"); } }

        var app = new Config.AppConfig();
        var acc = new Config.AccountConfig { Id = "selftest_" + Guid.NewGuid().ToString("N"), ServerUrl = server, AccountEmail = email };
        try
        {
            using (var backend = new VaultBackend(app, acc))
            {
                var login = await backend.LoginPasswordAsync(email, Encoding.UTF8.GetBytes(password), null, null, null);
                Check("login success", login.Status == LoginStatus.Success, login.Status + " " + login.Error);
                Check("unlocked after login", backend.Unlocked);
                Check("persisted session written", backend.HasPersistedSession);
                await backend.SyncAsync();
                sb.AppendLine($"    items after sync: {backend.Items.Count}");
                backend.Lock();
                Check("locked", !backend.Unlocked);
            }

            using (var backend2 = new VaultBackend(app, acc))
            {
                Check("persisted session survives new instance", backend2.HasPersistedSession);
                var unlock = await backend2.UnlockAsync(Encoding.UTF8.GetBytes(password));
                Check("unlock-from-state success", unlock == UnlockStatus.Success, unlock.ToString());
                Check("unlocked after unlock-from-state", backend2.Unlocked);

                var wrong = await backend2.UnlockAsync(Encoding.UTF8.GetBytes("definitely-wrong-password"));
                Check("wrong password rejected", wrong == UnlockStatus.WrongPassword, wrong.ToString());

                backend2.Logout();
                Check("logout clears persisted session", !backend2.HasPersistedSession);
            }
        }
        catch (Exception ex) { sb.AppendLine("  EXCEPTION: " + ex); }
        finally
        {
            try { if (System.IO.Directory.Exists(acc.DataDir)) System.IO.Directory.Delete(acc.DataDir, true); } catch { }
        }

        sb.Insert(0, $"VaultType backend facade test: {pass} passed, {fail} failed\n");
        return sb.ToString();
    }
}
