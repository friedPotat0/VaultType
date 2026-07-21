using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using VaultType.Vault.Models;

namespace VaultType.Vault;

// Thin HTTP layer over the Bitwarden/Vaultwarden identity + api endpoints. No crypto here - it just
// speaks the wire protocol. Both official and Vaultwarden expose /identity and /api under the same
// base host (the web-vault reverse proxy), so a single base URL is enough.
public sealed class VaultApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _base;
    private readonly string _deviceId;
    private readonly string _deviceName;

    public const string ClientId = "desktop";
    public const int DeviceTypeWindowsDesktop = 6;

    // The Bitwarden PROTOCOL version we speak, not VaultType's own version. Servers gate features
    // on this: Vaultwarden strips SSH-key ciphers (type 5) from /api/sync for clients older than
    // 2024.12.0, so reporting our real "1.0.0" silently loses every SSH key.
    public const string ClientVersion = "2025.6.0";

    public VaultApiClient(string serverUrl, string deviceIdentifier, string deviceName = "VaultType")
    {
        _base = serverUrl.TrimEnd('/');
        _deviceId = deviceIdentifier;
        _deviceName = deviceName;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(40) };
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Name", "desktop");
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Version", ClientVersion);
        _http.DefaultRequestHeaders.Add("Device-Type", DeviceTypeWindowsDesktop.ToString());
    }

    public string ServerUrl => _base;

    public async Task<PreloginResponse> PreloginAsync(string email, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{_base}/identity/accounts/prelogin",
            new { email }, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        var pre = await resp.Content.ReadFromJsonAsync<PreloginResponse>(Json.Options, ct).ConfigureAwait(false);
        return pre ?? throw new InvalidOperationException("Empty prelogin response.");
    }

    // Password grant. authHash is the base64 master-password auth hash (never the raw password).
    public Task<(TokenResponse token, string rawJson, bool ok)> TokenPasswordAsync(
        string email, string authHash, string? twoFactorToken, int? twoFactorProvider,
        bool remember2Fa, string? newDeviceOtp, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "password"),
            new("username", email),
            new("password", authHash),
            new("scope", "api offline_access"),
            new("client_id", ClientId),
            new("deviceType", DeviceTypeWindowsDesktop.ToString()),
            new("deviceIdentifier", _deviceId),
            new("deviceName", _deviceName),
        };
        if (!string.IsNullOrEmpty(twoFactorToken) && twoFactorProvider != null)
        {
            form.Add(new("twoFactorToken", twoFactorToken));
            form.Add(new("twoFactorProvider", twoFactorProvider.Value.ToString()));
            form.Add(new("twoFactorRemember", remember2Fa ? "1" : "0"));
        }
        if (!string.IsNullOrEmpty(newDeviceOtp))
            form.Add(new("newDeviceOtp", newDeviceOtp));

        return PostTokenAsync(form, email, ct);
    }

    // API-key grant (client_credentials). clientId = "user.<guid>", secret from the account page.
    // The secret arrives as wipeable bytes (the caller owns and zeroes them); it only becomes a
    // short-lived managed string here, for the unavoidable moment of building the form body -
    // FormUrlEncodedContent takes strings.
    public Task<(TokenResponse token, string rawJson, bool ok)> TokenApiKeyAsync(
        string clientId, byte[] clientSecret, string email, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("scope", "api"),
            new("client_id", clientId),
            new("client_secret", System.Text.Encoding.UTF8.GetString(clientSecret)),
            new("deviceType", DeviceTypeWindowsDesktop.ToString()),
            new("deviceIdentifier", _deviceId),
            new("deviceName", _deviceName),
        };
        return PostTokenAsync(form, email, ct);
    }

    public Task<(TokenResponse token, string rawJson, bool ok)> TokenRefreshAsync(
        string refreshToken, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("client_id", ClientId),
            new("refresh_token", refreshToken),
        };
        return PostTokenAsync(form, null, ct);
    }

    private async Task<(TokenResponse, string, bool)> PostTokenAsync(
        List<KeyValuePair<string, string>> form, string? email, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{_base}/identity/connect/token")
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (email != null)
            req.Headers.TryAddWithoutValidation("auth-email", Base64Url(Encoding.UTF8.GetBytes(email)));

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var token = JsonSerializer.Deserialize<TokenResponse>(raw, Json.Options) ?? new TokenResponse();
        return (token, raw, resp.IsSuccessStatusCode);
    }

    public async Task<(SyncResponse sync, string rawJson)> SyncAsync(string accessToken, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{_base}/api/sync?excludeDomains=true");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Sync failed ({(int)resp.StatusCode}): {Truncate(raw, 300)}");
        var sync = JsonSerializer.Deserialize<SyncResponse>(raw, Json.Options) ?? new SyncResponse();
        AttachRawCiphers(raw, sync);
        return (sync, raw);
    }

    // Give each cipher its own raw JSON (needed for read-modify-write edits). The parsed list keeps
    // server order, so we zip by index.
    private static void AttachRawCiphers(string raw, SyncResponse sync)
    {
        using var doc = JsonDocument.Parse(raw);
        if (!TryGetPropertyCI(doc.RootElement, "ciphers", out var arr) || arr.ValueKind != JsonValueKind.Array) return;
        int i = 0;
        foreach (var el in arr.EnumerateArray())
        {
            if (i >= sync.Ciphers.Count) break;
            sync.Ciphers[i].Raw = el.Clone();
            i++;
        }
    }

    private static bool TryGetPropertyCI(JsonElement obj, string name, out JsonElement value)
    {
        value = default;
        if (obj.ValueKind != JsonValueKind.Object) return false;
        foreach (var p in obj.EnumerateObject())
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) { value = p.Value; return true; }
        return false;
    }

    // PUT a full cipher object back (read-modify-write). cipherJson is the complete object.
    public async Task<string> PutCipherAsync(string accessToken, string cipherId, string cipherJson, CancellationToken ct = default)
        => await SendCipherAsync(HttpMethod.Put, $"{_base}/api/ciphers/{cipherId}", accessToken, cipherJson, ct).ConfigureAwait(false);

    // POST a new cipher; returns the created object JSON (contains the server-assigned id).
    public async Task<string> PostCipherAsync(string accessToken, string cipherJson, CancellationToken ct = default)
        => await SendCipherAsync(HttpMethod.Post, $"{_base}/api/ciphers", accessToken, cipherJson, ct).ConfigureAwait(false);

    public async Task DeleteCipherAsync(string accessToken, string cipherId, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Delete, $"{_base}/api/ciphers/{cipherId}");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException($"Delete cipher failed ({(int)resp.StatusCode}): {Truncate(raw, 300)}");
        }
    }

    private async Task<string> SendCipherAsync(HttpMethod method, string url, string accessToken, string cipherJson, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, url)
        {
            Content = new StringContent(cipherJson, Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"{method} cipher failed ({(int)resp.StatusCode}): {Truncate(raw, 300)}");
        return raw;
    }

    public static string Base64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];

    public void Dispose() => _http.Dispose();
}
