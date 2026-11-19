using System.Net.Http;
using System.Security.Cryptography;
using VaultType.Vault.Crypto;
using VaultType.Vault.Models;

namespace VaultType.Vault;

// A "log in with device" request from a browser, ready to be shown for approval.
public sealed class LoginRequest
{
    public string Id { get; init; } = "";
    public string PublicKey { get; init; } = "";   // base64 SPKI DER, exactly as listed
    public string Fingerprint { get; init; } = "";
    public string DeviceType { get; init; } = "";
    public string IpAddress { get; init; } = "";
    public string Country { get; init; } = "";
    public DateTimeOffset Created { get; init; }
}

public enum LoginAnswerResult { Approved, Denied, NoLongerValid }

// The approving side of Bitwarden's "log in with device": the web vault asks, VaultType (a signed-in
// device of the same account) answers by sending the user key, encrypted to the browser's one-off
// public key. Mirrors what the official desktop app does, including its checks.
public sealed partial class VaultBackend
{
    // Requests older than this are expired on the server (Bitwarden's UserRequestExpiration).
    public static readonly TimeSpan LoginRequestLifetime = TimeSpan.FromMinutes(15);

    // Pending browser login requests created at or after `since`. Listing needs no key material, so
    // it also works while the vault is locked (the stored refresh token gets an access token).
    public async Task<List<LoginRequest>> PendingLoginRequestsAsync(DateTimeOffset since, CancellationToken ct = default)
    {
        if (IsOffline) return new();
        _refreshToken ??= PersistedSession.Load(_statePath)?.RefreshToken;
        await EnsureAccessTokenAsync(ct).ConfigureAwait(false);
        var all = await Api().GetPendingAuthRequestsAsync(_accessToken!, ct).ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        string email = AccountEmail();
        return all
            .Where(r => !string.IsNullOrEmpty(r.Id) && !string.IsNullOrEmpty(r.PublicKey) && r.CreationDate != null)
            // The server only accepts an answer to the newest request per browser.
            .GroupBy(r => r.RequestDeviceIdentifier ?? r.Id)
            .Select(g => g.OrderByDescending(r => r.CreationDate).First())
            .Where(r => IsOpen(r, now) && r.CreationDate >= since)
            .Select(r => new LoginRequest
            {
                Id = r.Id!,
                PublicKey = r.PublicKey!,
                Fingerprint = FingerprintPhrase.For(email, Convert.FromBase64String(r.PublicKey!)),
                DeviceType = r.RequestDeviceType ?? "",
                IpAddress = r.RequestIpAddress ?? "",
                Country = r.RequestCountryName ?? "",
                Created = r.CreationDate!.Value,
            })
            .ToList();
    }

    // Answer a request the user has looked at. Approving needs the unlocked user key. The request is
    // read again first: if it was answered or expired meanwhile, or now carries a different public
    // key than the one whose fingerprint was shown, nothing is sent.
    public async Task<LoginAnswerResult> AnswerLoginRequestAsync(LoginRequest shown, bool approve, CancellationToken ct = default)
    {
        if (approve && (_crypto?.IsUnlocked != true || IsOffline))
            throw new InvalidOperationException("Account is locked.");
        await EnsureAccessTokenAsync(ct).ConfigureAwait(false);

        var current = await Api().GetAuthRequestAsync(_accessToken!, shown.Id, ct).ConfigureAwait(false);
        if (current == null || !IsOpen(current, DateTimeOffset.UtcNow)
            || !string.Equals(current.PublicKey, shown.PublicKey, StringComparison.Ordinal))
            return LoginAnswerResult.NoLongerValid;

        // A denial never carries the key (the official clients send it anyway; the server drops it).
        // Vaultwarden insists on a "key" string even then, so a refused null is retried as "".
        string? encryptedKey = approve ? EncryptUserKeyFor(shown.PublicKey) : null;
        try
        {
            await Api().PutAuthRequestAsync(_accessToken!, shown.Id, encryptedKey, _deviceId, approve, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (ex is not ServerUnreachableException)
        {
            if (approve) return LoginAnswerResult.NoLongerValid;   // answered elsewhere, superseded or expired
            try { await Api().PutAuthRequestAsync(_accessToken!, shown.Id, "", _deviceId, false, ct).ConfigureAwait(false); }
            catch (HttpRequestException retry) when (retry is not ServerUnreachableException) { return LoginAnswerResult.NoLongerValid; }
        }
        return approve ? LoginAnswerResult.Approved : LoginAnswerResult.Denied;
    }

    private static bool IsOpen(AuthRequestModel r, DateTimeOffset now)
        => r.RequestApproved != true && r.ResponseDate == null
           && r.CreationDate is { } created && now - created < LoginRequestLifetime;

    // The user key (enc || mac, 64 bytes) as an RSA-OAEP-SHA1 EncString ("4.<base64>") for the
    // requester's public key - the format the web vault decapsulates.
    private string EncryptUserKeyFor(string publicKeyB64)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyB64), out _);
        if (rsa.KeySize < 2048) throw new CryptographicException("The requester's key is too weak.");
        byte[] userKey = _crypto!.ExportUserKeyRaw();
        try
        {
            return "4." + Convert.ToBase64String(rsa.Encrypt(userKey, RSAEncryptionPadding.OaepSHA1));
        }
        finally { CryptographicOperations.ZeroMemory(userKey); }
    }

    private string AccountEmail()
        => PersistedSession.Load(_statePath)?.Email is { Length: > 0 } e ? e : _acc.AccountEmail;
}
