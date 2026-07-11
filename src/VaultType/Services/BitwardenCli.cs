using System.IO;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using VaultType.Config;
using VaultType.Models;
using VaultType.Security;

namespace VaultType.Services;

public sealed record StatusInfo(string ServerUrl, string Status, string UserEmail, string UserId);

// Thin wrapper around the official bw.exe - that's where the actual crypto happens.
public sealed class BitwardenCli
{
    private readonly string _exe;
    private readonly AppConfig _cfg;

    public BitwardenCli(AppConfig cfg)
    {
        _cfg = cfg;
        _exe = ResolveExe();
    }

    public string ExePath => _exe;
    public bool ExeExists => File.Exists(_exe);

    private static string ResolveExe()
    {
        var local = Path.Combine(AppContext.BaseDirectory, "bw.exe");
        // Prefer a bw.exe placed next to the app; otherwise use (and auto-download to)
        // the per-user data directory.
        return File.Exists(local) ? local : Path.Combine(AppConfig.DataDir, "bw.exe");
    }

    private Dictionary<string, string> BaseEnv()
    {
        var env = new Dictionary<string, string>
        {
            ["BITWARDENCLI_APPDATA_DIR"] = AppConfig.BwDataDir,
            ["BW_NOINTERACTION"] = "true",
            ["BW_RAW"] = "true",
            ["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
        };
        return env;
    }

    public bool ConfigServer(string url, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(url)) return true;
        using var r = NativeProcess.Run(_exe, $"config server {Quote(url)}", BaseEnv());
        if (r.ExitCode != 0) { error = Clean(r.StdErr); return false; }
        return true;
    }

    public StatusInfo? Status()
    {
        using var r = NativeProcess.Run(_exe, "status", BaseEnv());
        try
        {
            // status contains no secrets -> a managed copy is harmless
            using var doc = JsonDocument.Parse(r.OutSpan.ToArray());
            var root = doc.RootElement;
            return new StatusInfo(
                Str(root, "serverUrl"), Str(root, "status"),
                Str(root, "userEmail"), Str(root, "userId"));
        }
        catch { return null; }
    }

    // Unlock the vault. Master password stays a SecureString; we get back the session key.
    public SecureString? Unlock(SecureString master, out string error)
    {
        error = "";
        using var r = NativeProcess.Run(_exe, "unlock --raw --passwordenv BW_PASSWORD", BaseEnv(), "BW_PASSWORD", master);
        if (r.ExitCode != 0)
        {
            error = Clean(r.StdErr);
            if (string.IsNullOrWhiteSpace(error)) error = "Unlock failed (wrong master password?).";
            return null;
        }
        return BytesToSecure(r.OutSpan);
    }

    // Email + master password sign-in, with an optional 2FA code (0 = authenticator, 1 = email, 3 = YubiKey).
    public SecureString? Login(string email, SecureString master, string? twoFactorCode, int twoFactorMethod, out string error)
    {
        error = "";
        string args = $"login {Quote(email)} --raw --passwordenv BW_PASSWORD";
        if (!string.IsNullOrWhiteSpace(twoFactorCode))
            args += $" --method {twoFactorMethod} --code {Quote(twoFactorCode.Trim())}";
        using var r = NativeProcess.Run(_exe, args, BaseEnv(), "BW_PASSWORD", master);
        if (r.ExitCode != 0)
        {
            error = Clean(r.StdErr);
            if (string.IsNullOrWhiteSpace(error)) error = "Sign-in failed.";
            return null;
        }
        return BytesToSecure(r.OutSpan);
    }

    // Personal API-key sign-in - the sane option for bitwarden.com since it skips the
    // CAPTCHA/bot check and 2FA. Only authenticates the CLI; the vault stays locked until
    // you unlock it with the master password afterwards.
    public bool LoginApiKey(string clientId, SecureString clientSecret, out string error)
    {
        error = "";
        var env = BaseEnv();
        env["BW_CLIENTID"] = clientId.Trim();
        using var r = NativeProcess.Run(_exe, "login --apikey", env, "BW_CLIENTSECRET", clientSecret);
        if (r.ExitCode != 0)
        {
            error = Clean(r.StdErr);
            if (string.IsNullOrWhiteSpace(error)) error = "API key sign-in failed.";
            return false;
        }
        return true;
    }

    public void Sync(SecureString session)
    {
        using var _ = NativeProcess.Run(_exe, "sync", BaseEnv(), "BW_SESSION", session);
    }

    public void Lock(SecureString session)
    {
        try { using var _ = NativeProcess.Run(_exe, "lock", BaseEnv(), "BW_SESSION", session); }
        catch { /* best effort */ }
    }

    // Add a URI to an item so it gets suggested next time (get -> tweak -> edit). The item
    // JSON round-trips through memory once; the base64 payload goes to bw.exe over stdin only,
    // never on the command line. Only runs when the user confirms it.
    public bool AddUri(SecureString session, string itemId, string uri, out string error)
    {
        error = "";
        using var got = NativeProcess.Run(_exe, $"get item {Quote(itemId)}", BaseEnv(), "BW_SESSION", session);
        if (got.ExitCode != 0) { error = Clean(got.StdErr); return false; }

        string? edited = InsertUri(Encoding.UTF8.GetString(got.OutSpan), uri);
        if (edited == null) { error = "Could not modify item."; return false; }

        byte[] payload = Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(edited)));
        using var res = NativeProcess.Run(_exe, $"edit item {Quote(itemId)}", BaseEnv(), "BW_SESSION", session, payload);
        if (res.ExitCode != 0) { error = Clean(res.StdErr); return false; }
        return true;
    }

    private static string? InsertUri(string json, string uri)
    {
        try
        {
            var node = JsonNode.Parse(json);
            if (node?["login"] is not JsonObject login) return null;
            if (login["uris"] is not JsonArray uris)
            {
                uris = new JsonArray();
                login["uris"] = uris;
            }
            uris.Add(new JsonObject { ["match"] = null, ["uri"] = uri });
            return node!.ToJsonString();
        }
        catch { return null; }
    }

    // Load all login entries; the secrets get encrypted in RAM straight away.
    public List<VaultItem> ListItems(SecureString session, SecretProtector protector, out string error)
    {
        error = "";
        using var r = NativeProcess.Run(_exe, "list items", BaseEnv(), "BW_SESSION", session);
        if (r.ExitCode != 0)
        {
            error = Clean(r.StdErr);
            return new List<VaultItem>();
        }
        try { return ParseItems(r.OutSpan, protector, _cfg.AutoTypeFieldName); }
        catch (Exception ex) { error = ex.Message; return new List<VaultItem>(); }
        // r.Dispose() zeroes the stdout bytes (including all plaintext passwords)
    }

    // ---------- byte-wise JSON parsing (no managed string holding plaintext) ----------

    private static List<VaultItem> ParseItems(ReadOnlySpan<byte> json, SecretProtector p, string fieldName)
    {
        var items = new List<VaultItem>();
        var reader = new Utf8JsonReader(json, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) return items;
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray) break;
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                var it = ParseItem(ref reader, p, fieldName);
                if (it != null) items.Add(it);
            }
        }
        return items;
    }

    private static VaultItem? ParseItem(ref Utf8JsonReader reader, SecretProtector p, string fieldName)
    {
        var it = new VaultItem();
        int type = 0;
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject) break;
            if (reader.TokenType != JsonTokenType.PropertyName) continue;

            if (reader.ValueTextEquals("id")) { reader.Read(); it.Id = ReadStr(ref reader); }
            else if (reader.ValueTextEquals("type")) { reader.Read(); type = ReadInt(ref reader); }
            else if (reader.ValueTextEquals("name")) { reader.Read(); it.Name = ReadStr(ref reader); }
            else if (reader.ValueTextEquals("reprompt")) { reader.Read(); it.Reprompt = ReadInt(ref reader) == 1; }
            else if (reader.ValueTextEquals("login")) { reader.Read(); if (reader.TokenType == JsonTokenType.StartObject) ParseLogin(ref reader, it, p); }
            else if (reader.ValueTextEquals("fields")) { reader.Read(); if (reader.TokenType == JsonTokenType.StartArray) ParseFields(ref reader, it, fieldName); }
            else { reader.Read(); SkipValue(ref reader); }
        }
        return type == 1 ? it : null; // logins only
    }

    private static void ParseLogin(ref Utf8JsonReader reader, VaultItem it, SecretProtector p)
    {
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject) break;
            if (reader.TokenType != JsonTokenType.PropertyName) continue;

            if (reader.ValueTextEquals("username")) { reader.Read(); it.Username = ReadStr(ref reader); }
            else if (reader.ValueTextEquals("password")) { reader.Read(); it.Password = ProtectCurrent(ref reader, p); }
            else if (reader.ValueTextEquals("totp")) { reader.Read(); it.TotpSecret = ProtectCurrent(ref reader, p); it.HasTotp = it.TotpSecret != null; }
            else if (reader.ValueTextEquals("uris")) { reader.Read(); if (reader.TokenType == JsonTokenType.StartArray) ParseUris(ref reader, it); }
            else { reader.Read(); SkipValue(ref reader); }
        }
    }

    private static void ParseFields(ref Utf8JsonReader reader, VaultItem it, string fieldName)
    {
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray) break;
            if (reader.TokenType != JsonTokenType.StartObject) continue;

            string name = "", value = "";
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject) break;
                if (reader.TokenType != JsonTokenType.PropertyName) continue;
                if (reader.ValueTextEquals("name")) { reader.Read(); name = ReadStr(ref reader); }
                else if (reader.ValueTextEquals("value")) { reader.Read(); value = ReadStr(ref reader); }
                else { reader.Read(); SkipValue(ref reader); }
            }
            if (value.Length > 0 && string.Equals(name, fieldName, StringComparison.OrdinalIgnoreCase))
                it.CustomSequence = value;
        }
    }

    private static void ParseUris(ref Utf8JsonReader reader, VaultItem it)
    {
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray) break;
            if (reader.TokenType != JsonTokenType.StartObject) continue;

            var u = new ItemUri();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject) break;
                if (reader.TokenType != JsonTokenType.PropertyName) continue;
                if (reader.ValueTextEquals("uri")) { reader.Read(); u.Value = ReadStr(ref reader); }
                else if (reader.ValueTextEquals("match")) { reader.Read(); u.MatchType = ReadInt(ref reader); }
                else { reader.Read(); SkipValue(ref reader); }
            }
            if (u.Value.Length > 0) { Matcher.FillHostDomain(u); it.Uris.Add(u); }
        }
    }

    // Copies a JSON string UNESCAPED into a locked buffer and encrypts it immediately.
    private static SecretBox? ProtectCurrent(ref Utf8JsonReader reader, SecretProtector p)
    {
        if (reader.TokenType != JsonTokenType.String) return null;
        int cap = reader.HasValueSequence ? (int)reader.ValueSequence.Length : reader.ValueSpan.Length;
        if (cap <= 0) return null;
        using var tmp = new LockedBuffer(cap);
        int n = reader.CopyString(tmp.Span);
        if (n <= 0) return null;
        return p.Protect(tmp.Span.Slice(0, n));
    }

    private static string ReadStr(ref Utf8JsonReader reader)
        => reader.TokenType == JsonTokenType.String ? (reader.GetString() ?? "") : "";

    private static int ReadInt(ref Utf8JsonReader reader)
        => reader.TokenType == JsonTokenType.Number && reader.TryGetInt32(out int v) ? v : 0;

    private static void SkipValue(ref Utf8JsonReader reader)
    {
        if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
            reader.Skip();
    }

    // ---------- helpers ----------

    private static SecureString BytesToSecure(ReadOnlySpan<byte> ascii)
    {
        int end = ascii.Length;
        while (end > 0 && (ascii[end - 1] == (byte)'\n' || ascii[end - 1] == (byte)'\r' || ascii[end - 1] == (byte)' ' || ascii[end - 1] == (byte)'\t')) end--;
        int start = 0;
        while (start < end && (ascii[start] == (byte)' ' || ascii[start] == (byte)'\t')) start++;
        var ss = new SecureString();
        for (int i = start; i < end; i++) ss.AppendChar((char)ascii[i]);
        ss.MakeReadOnly();
        return ss;
    }

    private static string Str(JsonElement e, string prop)
        => e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : "";

    private static string Quote(string s) => "\"" + s.Replace("\"", "") + "\"";

    private static string Clean(string s) => s.Replace("\r", " ").Replace("\n", " ").Trim();
}
