using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using VaultType.Config;
using VaultType.Models;
using VaultType.Security;
using VaultType.Vault.Crypto;
using VaultType.Vault.Models;

namespace VaultType.Vault;

public enum LoginStatus { Success, TwoFactorRequired, NewDeviceVerificationRequired, Failed }
public enum UnlockStatus { Success, WrongPassword, NeedsLogin, Failed }

public sealed class LoginResult
{
    public LoginStatus Status { get; init; }
    public string Error { get; init; } = "";
    public string? TwoFactorProvidersJson { get; init; }
    public static LoginResult Ok() => new() { Status = LoginStatus.Success };
    public static LoginResult Fail(string e) => new() { Status = LoginStatus.Failed, Error = e };
}

// The native replacement for BitwardenCli: one instance per account, holding that account's HTTP
// client, decrypted key material, decrypted items and OAuth tokens. All Bitwarden/Vaultwarden crypto
// happens in-process now (see AccountCrypto / Kdf / EncString). Verified end-to-end against a real
// Vaultwarden and Bitwarden.eu (see VaultLiveTest).
public sealed class VaultBackend : IDisposable
{
    private readonly AppConfig _app;
    private readonly AccountConfig _acc;
    private readonly string _statePath;

    private VaultApiClient? _api;
    private AccountCrypto? _crypto;
    private List<CipherModel> _ciphers = new();

    // Serialises the sync/decrypt state swap. CreatePasskeyAsync fires a background sync, which must
    // not overlap another DecryptAll while it replaces the Protector and item lists together.
    private readonly object _decryptGate = new();

    private string? _accessToken;
    private DateTimeOffset _accessExpiry;
    private string? _refreshToken;
    private string _deviceId;

    private bool _mockUnlocked;

    public SecretProtector? Protector { get; private set; }
    public List<VaultItem> Items { get; private set; } = new();
    public List<SshKeyEntry> SshKeys { get; private set; } = new();
    public List<Fido2Entry> Passkeys { get; private set; } = new();
    public bool Unlocked => _crypto?.IsUnlocked == true || _mockUnlocked;
    public bool HasPersistedSession => PersistedSession.Load(_statePath) != null;

    // Dev/preview only: pretend to be unlocked with the given items so the --screenshots
    // mode can render item-bearing windows without a real vault.
    public void LoadMockUnlocked(List<VaultItem> items)
    {
        Protector?.Dispose();
        Protector = new SecretProtector();
        Items = items;
        _mockUnlocked = true;
    }

    // Dev/preview only: attach mock SSH keys (display data only) to the unlocked session.
    public void LoadMockSshKeys(List<SshKeyEntry> keys)
    {
        SshKeys = keys;
        _mockUnlocked = true;
    }

    public VaultBackend(AppConfig app, AccountConfig acc)
    {
        _app = app;
        _acc = acc;
        _statePath = Path.Combine(acc.DataDir, "session.json");
        _deviceId = PersistedSession.Load(_statePath)?.DeviceIdentifier ?? Guid.NewGuid().ToString();
    }

    private VaultApiClient Api()
    {
        string server = string.IsNullOrWhiteSpace(_acc.ServerUrl) ? AccountConfig.UsCloud : _acc.ServerUrl;
        if (_api == null || !string.Equals(_api.ServerUrl, server.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
        {
            _api?.Dispose();
            _api = new VaultApiClient(server, _deviceId);
        }
        return _api;
    }

    // ---- sign-in (password grant). Takes ownership of masterPassword and wipes it. ----
    public async Task<LoginResult> LoginPasswordAsync(string email, byte[] masterPassword,
        string? twoFactorCode, int? twoFactorProvider, string? newDeviceOtp, CancellationToken ct = default)
    {
        var api = Api();
        byte[]? masterKey = null;
        try
        {
            var pre = await api.PreloginAsync(email, ct).ConfigureAwait(false);
            var kdf = ToKdf(pre);
            masterKey = Kdf.DeriveMasterKey(email, masterPassword, kdf);
            string authHash = Kdf.MasterPasswordAuthHash(masterKey, masterPassword);

            var (token, raw, ok) = await api.TokenPasswordAsync(email, authHash, twoFactorCode, twoFactorProvider, false, newDeviceOtp, ct).ConfigureAwait(false);
            if (!ok)
            {
                if (token.Requires2Fa)
                    return new LoginResult { Status = LoginStatus.TwoFactorRequired, TwoFactorProvidersJson = token.TwoFactorProviders2.ToString() };
                string desc = token.ErrorDescription ?? token.Error ?? "Sign-in failed.";
                if (desc.Contains("device", StringComparison.OrdinalIgnoreCase) && desc.Contains("verif", StringComparison.OrdinalIgnoreCase))
                    return new LoginResult { Status = LoginStatus.NewDeviceVerificationRequired, Error = desc };
                return LoginResult.Fail(desc);
            }

            await CompleteAuthAsync(email, kdf, masterKey, token, ct).ConfigureAwait(false);
            return LoginResult.Ok();
        }
        catch (HttpRequestException ex) { return LoginResult.Fail(ex.Message); }
        finally
        {
            if (masterKey != null) CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(masterPassword);
        }
    }

    // ---- API-key sign-in (client_credentials). Still needs the master password to decrypt. ----
    public async Task<LoginResult> LoginApiKeyAsync(string clientId, byte[] clientSecret, string email,
        byte[] masterPassword, CancellationToken ct = default)
    {
        var api = Api();
        byte[]? masterKey = null;
        try
        {
            var (token, raw, ok) = await api.TokenApiKeyAsync(clientId, clientSecret, email, ct).ConfigureAwait(false);
            if (!ok) return LoginResult.Fail(token.ErrorDescription ?? token.Error ?? "API key sign-in failed.");

            var pre = await api.PreloginAsync(email, ct).ConfigureAwait(false);
            var kdf = ToKdf(pre);
            masterKey = Kdf.DeriveMasterKey(email, masterPassword, kdf);
            await CompleteAuthAsync(email, kdf, masterKey, token, ct).ConfigureAwait(false);
            return LoginResult.Ok();
        }
        catch (HttpRequestException ex) { return LoginResult.Fail(ex.Message); }
        finally
        {
            if (masterKey != null) CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(masterPassword);
            CryptographicOperations.ZeroMemory(clientSecret);
        }
    }

    // Shared tail: unwrap keys, persist state, sync + decrypt.
    private async Task CompleteAuthAsync(string email, KdfConfig kdf, byte[] masterKey, TokenResponse token, CancellationToken ct)
    {
        _accessToken = token.AccessToken;
        _accessExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, token.ExpiresIn) - 60);
        _refreshToken = token.RefreshToken;

        // First sync gives us the authoritative profile keys.
        var (sync, _) = await Api().SyncAsync(_accessToken!, ct).ConfigureAwait(false);
        string userKeyEnc = sync.Profile?.Key ?? token.Key ?? throw new InvalidOperationException("No protected user key returned.");
        string? privKeyEnc = sync.Profile?.PrivateKey ?? token.PrivateKey;

        _crypto?.Dispose();
        _crypto = new AccountCrypto();
        _crypto.Unlock(masterKey, userKeyEnc, privKeyEnc, sync.Profile?.Organizations ?? new());

        SaveState(email, kdf, userKeyEnc, privKeyEnc);
        DecryptAll(sync);
        var st = PersistedSession.Load(_statePath);
        if (st != null) RearmEphemeralPin(st);
    }

    // ---- unlock from persisted state (after a restart / lock). Wipes masterPassword. ----
    public async Task<UnlockStatus> UnlockAsync(byte[] masterPassword, CancellationToken ct = default)
    {
        var state = PersistedSession.Load(_statePath);
        if (state?.ProtectedUserKey == null || state.RefreshToken == null)
        { CryptographicOperations.ZeroMemory(masterPassword); return UnlockStatus.NeedsLogin; }

        byte[]? masterKey = null;
        try
        {
            var kdf = new KdfConfig { Type = (KdfType)state.Kdf, Iterations = state.KdfIterations, MemoryMiB = state.KdfMemory, Parallelism = state.KdfParallelism };
            masterKey = Kdf.DeriveMasterKey(state.Email ?? _acc.AccountEmail, masterPassword, kdf);

            var crypto = new AccountCrypto();
            try { crypto.Unlock(masterKey, state.ProtectedUserKey, state.ProtectedPrivateKey, Array.Empty<OrganizationModel>()); }
            catch (CryptographicException) { crypto.Dispose(); return UnlockStatus.WrongPassword; }

            _crypto?.Dispose();
            _crypto = crypto;
            _refreshToken = state.RefreshToken;

            if (!await RefreshAccessTokenAsync(ct).ConfigureAwait(false))
            {
                // Offline or refresh expired: keep the vault unlocked from cache is not possible
                // without ciphers; require a fresh login.
                return UnlockStatus.NeedsLogin;
            }
            var (sync, _) = await Api().SyncAsync(_accessToken!, ct).ConfigureAwait(false);
            // Re-unwrap org keys now that we have the profile (unlock above used no orgs).
            _crypto.Dispose();
            _crypto = new AccountCrypto();
            _crypto.Unlock(masterKey, sync.Profile?.Key ?? state.ProtectedUserKey, sync.Profile?.PrivateKey ?? state.ProtectedPrivateKey, sync.Profile?.Organizations ?? new());
            DecryptAll(sync);
            RearmEphemeralPin(state);
            return UnlockStatus.Success;
        }
        catch (HttpRequestException) { return UnlockStatus.Failed; }
        finally
        {
            if (masterKey != null) CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(masterPassword);
        }
    }

    // ---- PIN unlock (Bitwarden-style) ----
    // The PIN-derived key (same KDF as the master password) wraps the user key. With
    // "require master password on restart" the envelope lives only in this process; the PIN is
    // additionally persisted wrapped by the user key so a master-password unlock can re-arm it.

    // accountId -> RAM-only PIN envelope (survives lock, not a restart)
    private static readonly Dictionary<string, string> EphemeralPinEnvelopes = new();

    public bool PinAvailable
    {
        get
        {
            var state = PersistedSession.Load(_statePath);
            if (state?.RefreshToken == null) return false;
            lock (EphemeralPinEnvelopes)
                return state.PinProtectedUserKey != null || EphemeralPinEnvelopes.ContainsKey(_acc.Id);
        }
    }

    // Enroll a PIN for this (unlocked) account. Wipes pin.
    public void EnrollPin(byte[] pin, bool requireMasterOnRestart)
    {
        try
        {
            var state = PersistedSession.Load(_statePath)
                ?? throw new InvalidOperationException("No persisted session.");
            if (_crypto?.IsUnlocked != true) throw new InvalidOperationException("Account is locked.");

            string envelope = BuildPinEnvelope(state, pin);
            state.ProtectedPin = _crypto.EncryptWithUserKey(Convert.ToBase64String(pin));
            state.PinRequiresMasterPasswordOnRestart = requireMasterOnRestart;
            if (requireMasterOnRestart)
            {
                state.PinProtectedUserKey = null;
                lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes[_acc.Id] = envelope;
            }
            else
            {
                state.PinProtectedUserKey = envelope;
                lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes.Remove(_acc.Id);
            }
            state.Save(_statePath);
        }
        finally { CryptographicOperations.ZeroMemory(pin); }
    }

    public void RemovePin()
    {
        lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes.Remove(_acc.Id);
        var state = PersistedSession.Load(_statePath);
        if (state == null) return;
        state.PinProtectedUserKey = null;
        state.ProtectedPin = null;
        state.Save(_statePath);
    }

    // Wrap the current user key with a key derived from the PIN (does not wipe pin).
    private string BuildPinEnvelope(PersistedSession state, byte[] pin)
    {
        var kdf = new KdfConfig { Type = (KdfType)state.Kdf, Iterations = state.KdfIterations, MemoryMiB = state.KdfMemory, Parallelism = state.KdfParallelism };
        byte[] pinKey = Kdf.DeriveMasterKey(state.Email ?? _acc.AccountEmail, pin, kdf);
        byte[]? userKeyRaw = null;
        try
        {
            using var stretched = Kdf.StretchMasterKey(pinKey);
            userKeyRaw = _crypto!.ExportUserKeyRaw();
            return EncString.EncryptSymmetric(userKeyRaw, stretched);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinKey);
            if (userKeyRaw != null) CryptographicOperations.ZeroMemory(userKeyRaw);
        }
    }

    // After a successful master-password unlock, rebuild the RAM-only PIN envelope from the
    // persisted protected PIN (so the PIN works again until the next restart).
    private void RearmEphemeralPin(PersistedSession state)
    {
        if (!state.PinRequiresMasterPasswordOnRestart || state.ProtectedPin == null || _crypto?.IsUnlocked != true) return;
        lock (EphemeralPinEnvelopes) { if (EphemeralPinEnvelopes.ContainsKey(_acc.Id)) return; }
        byte[]? pin = null;
        try
        {
            pin = Convert.FromBase64String(ProtectedPinPlain(state));
            string envelope = BuildPinEnvelope(state, pin);
            lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes[_acc.Id] = envelope;
        }
        catch { /* a broken PIN envelope only disables PIN unlock */ }
        finally { if (pin != null) CryptographicOperations.ZeroMemory(pin); }
    }

    private string ProtectedPinPlain(PersistedSession state)
    {
        var key = SymmetricCryptoKey.FromRaw(_crypto!.ExportUserKeyRaw());
        try { return EncString.Parse(state.ProtectedPin!).DecryptToString(key); }
        finally { key.Dispose(); }
    }

    // After this many consecutive wrong PINs the PIN envelope is dropped and the master password is
    // required again, throttling online PIN brute-force (Bitwarden's "5 attempts then log out").
    private const int MaxPinAttempts = 5;

    // Records a wrong-PIN attempt and, once the limit is hit, removes the PIN envelope from disk and
    // RAM so only the master password can unlock. The counter is persisted so a restart can't reset it.
    private UnlockStatus RegisterPinFailure(PersistedSession state)
    {
        state.PinFailedAttempts++;
        bool exhausted = state.PinFailedAttempts >= MaxPinAttempts;
        if (exhausted)
        {
            state.PinProtectedUserKey = null;
            state.ProtectedPin = null;
            state.PinFailedAttempts = 0;
            lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes.Remove(_acc.Id);
        }
        try { state.Save(_statePath); } catch { }
        return exhausted ? UnlockStatus.NeedsLogin : UnlockStatus.WrongPassword;
    }

    // Unlock from the PIN envelope (RAM or disk). Wipes pin.
    public async Task<UnlockStatus> UnlockWithPinAsync(byte[] pin, CancellationToken ct = default)
    {
        byte[]? pinKey = null;
        byte[]? userKeyRaw = null;
        try
        {
            var state = PersistedSession.Load(_statePath);
            if (state?.RefreshToken == null) return UnlockStatus.NeedsLogin;
            string? envelope = state.PinProtectedUserKey;
            if (envelope == null)
                lock (EphemeralPinEnvelopes) EphemeralPinEnvelopes.TryGetValue(_acc.Id, out envelope);
            if (envelope == null) return UnlockStatus.NeedsLogin;

            var kdf = new KdfConfig { Type = (KdfType)state.Kdf, Iterations = state.KdfIterations, MemoryMiB = state.KdfMemory, Parallelism = state.KdfParallelism };
            pinKey = Kdf.DeriveMasterKey(state.Email ?? _acc.AccountEmail, pin, kdf);
            using (var stretched = Kdf.StretchMasterKey(pinKey))
            {
                try { userKeyRaw = EncString.Parse(envelope).DecryptSymmetric(stretched); }
                catch (CryptographicException) { return RegisterPinFailure(state); }
            }

            var crypto = new AccountCrypto();
            crypto.UnlockWithUserKeyRaw((byte[])userKeyRaw.Clone(), state.ProtectedPrivateKey, Array.Empty<OrganizationModel>());
            _crypto?.Dispose();
            _crypto = crypto;
            _refreshToken = state.RefreshToken;

            if (!await RefreshAccessTokenAsync(ct).ConfigureAwait(false)) return UnlockStatus.NeedsLogin;
            var (sync, _) = await Api().SyncAsync(_accessToken!, ct).ConfigureAwait(false);

            // Re-unlock with the profile's org keys now that we have them.
            _crypto.Dispose();
            _crypto = new AccountCrypto();
            _crypto.UnlockWithUserKeyRaw((byte[])userKeyRaw.Clone(),
                sync.Profile?.PrivateKey ?? state.ProtectedPrivateKey, sync.Profile?.Organizations ?? new());
            // Correct PIN: clear the failure counter.
            if (state.PinFailedAttempts != 0)
            {
                state.PinFailedAttempts = 0;
                try { state.Save(_statePath); } catch { }
            }
            DecryptAll(sync);
            return UnlockStatus.Success;
        }
        catch (HttpRequestException) { return UnlockStatus.Failed; }
        finally
        {
            if (pinKey != null) CryptographicOperations.ZeroMemory(pinKey);
            if (userKeyRaw != null) CryptographicOperations.ZeroMemory(userKeyRaw);
            CryptographicOperations.ZeroMemory(pin);
        }
    }

    public async Task SyncAsync(CancellationToken ct = default)
    {
        if (!Unlocked) return;
        await EnsureAccessTokenAsync(ct).ConfigureAwait(false);
        var (sync, _) = await Api().SyncAsync(_accessToken!, ct).ConfigureAwait(false);
        DecryptAll(sync);
    }

    // Add a URI to an item (read-modify-write), then re-sync so the new URI is reflected.
    public async Task<bool> AddUriAsync(string itemId, string uri, CancellationToken ct = default)
    {
        if (!Unlocked) return false;
        var cipher = _ciphers.FirstOrDefault(c => c.Id == itemId);
        if (cipher == null || _crypto == null) return false;
        await EnsureAccessTokenAsync(ct).ConfigureAwait(false);
        string body = CipherJson.BuildAddUriBody(cipher, _crypto.EncryptForCipher(cipher, uri));
        await Api().PutCipherAsync(_accessToken!, itemId, body, ct).ConfigureAwait(false);
        await SyncAsync(ct).ConfigureAwait(false);
        return true;
    }

    // Create a passkey for a relying party: generate a fresh P-256 key, store it as a new login
    // cipher with a fido2Credentials entry, and return the wire credential id plus the COSE public
    // key for the attestation object. Returns null when locked or the server rejects the item.
    public async Task<(byte[] CredentialId, System.Security.Cryptography.ECParameters PublicKey)?> CreatePasskeyAsync(
        string rpId, string? rpName, byte[] userId, string? userName, string? userDisplayName,
        bool discoverable, CancellationToken ct = default)
    {
        if (!Unlocked || _crypto == null) return null;

        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        byte[] pkcs8 = ecdsa.ExportPkcs8PrivateKey();
        var credentialGuid = Guid.NewGuid();
        try
        {
            string E(string v) => _crypto.EncryptWithUserKey(v);
            string? EOpt(string? v) => string.IsNullOrEmpty(v) ? null : _crypto.EncryptWithUserKey(v);

            var cred = new Fido2CredentialEnc
            {
                CredentialId = E(credentialGuid.ToString()),
                KeyType = E("public-key"),
                KeyAlgorithm = E("ECDSA"),
                KeyCurve = E("P-256"),
                KeyValue = E(VaultApiClient.Base64Url(pkcs8)),
                RpId = E(rpId),
                RpName = EOpt(rpName),
                UserHandle = userId.Length > 0 ? E(VaultApiClient.Base64Url(userId)) : null,
                UserName = EOpt(userName),
                UserDisplayName = EOpt(userDisplayName),
                Counter = E("0"),
                Discoverable = E(discoverable ? "true" : "false"),
            };

            string name = string.IsNullOrEmpty(rpName) ? rpId : rpName!;
            string body = CipherJson.BuildCreateFido2Login(
                E(name), EOpt(userName), E("https://" + rpId), cred);

            await EnsureAccessTokenAsync(ct).ConfigureAwait(false);
            await Api().PostCipherAsync(_accessToken!, body, ct).ConfigureAwait(false);

            // Refresh local state in the background: the ceremony response must not wait on a full
            // sync, or slow servers push the whole WebAuthn operation past its client timeout.
            _ = Task.Run(async () =>
            {
                try { await SyncAsync(CancellationToken.None).ConfigureAwait(false); }
                catch { }
            }, CancellationToken.None);

            return (credentialGuid.ToByteArray(bigEndian: true), ecdsa.ExportParameters(false));
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(pkcs8); }
    }

    // Verify a re-entered master password against the persisted state (offline, no network). Used
    // for the master-password reprompt on sensitive actions. Wipes masterPassword.
    public bool VerifyMasterPassword(byte[] masterPassword)
    {
        try
        {
            var state = PersistedSession.Load(_statePath);
            if (state?.ProtectedUserKey == null) return false;
            var kdf = new KdfConfig { Type = (KdfType)state.Kdf, Iterations = state.KdfIterations, MemoryMiB = state.KdfMemory, Parallelism = state.KdfParallelism };
            byte[] mk = Kdf.DeriveMasterKey(state.Email ?? _acc.AccountEmail, masterPassword, kdf);
            try
            {
                using var stretched = Kdf.StretchMasterKey(mk);
                _ = EncString.Parse(state.ProtectedUserKey).DecryptSymmetric(stretched);   // throws if wrong
                return true;
            }
            catch (CryptographicException) { return false; }
            finally { CryptographicOperations.ZeroMemory(mk); }
        }
        finally { CryptographicOperations.ZeroMemory(masterPassword); }
    }

    public void Lock()
    {
        _crypto?.Dispose(); _crypto = null;
        Protector?.Dispose(); Protector = null;
        Items = new List<VaultItem>();
        SshKeys = new List<SshKeyEntry>();
        Passkeys = new List<Fido2Entry>();
        _ciphers = new List<CipherModel>();
        _accessToken = null;
        // Keep the persisted session (refresh token + protected keys) so the vault can be unlocked
        // again without a full sign-in.
    }

    public void Logout()
    {
        Lock();
        _refreshToken = null;
        PersistedSession.Delete(_statePath);
        SshKeyMeta.Delete(_acc.SshMetaPath);
        PasskeyMeta.Delete(_acc.PasskeyMetaPath);
    }

    // ---- internals ----

    private void DecryptAll(SyncResponse sync)
    {
        // Serialise the state swap so a background sync (CreatePasskeyAsync fires one off) can't
        // overlap another DecryptAll while it replaces the Protector and item lists together. Reveal
        // is guarded inside SecretProtector, so a swap during an in-flight reveal fails cleanly
        // rather than corrupting.
        lock (_decryptGate)
        {
            // Every successful sync path (login, unlock, manual/background sync) ends here, so this
            // is the one spot that stamps the account's last-sync time. Persisting is the caller's job.
            _acc.LastSyncUtc = DateTimeOffset.UtcNow;
            _ciphers = sync.Ciphers;
            Protector?.Dispose();
            Protector = new SecretProtector();
            var items = new List<VaultItem>();
            var sshKeys = new List<SshKeyEntry>();
            var passkeys = new List<Fido2Entry>();
            foreach (var c in sync.Ciphers)
            {
                try
                {
                    if (c.Type == 1)
                    {
                        var it = _crypto!.DecryptLogin(c, Protector, _app.AutoTypeFieldName);
                        if (it != null) items.Add(it);
                        passkeys.AddRange(_crypto!.DecryptFido2(c, Protector));
                    }
                    else if (c.Type == 5)
                    {
                        var k = _crypto!.DecryptSshKey(c, Protector);
                        if (k != null) sshKeys.Add(k);
                    }
                }
                catch
                {
                    // skip an item we can't decrypt rather than fail the whole vault
                }
            }
            Items = items;
            SshKeys = sshKeys;
            Passkeys = passkeys;
            // Cache the public metadata so agent/picker can advertise keys and passkeys while locked.
            SshKeyMeta.Save(_acc.SshMetaPath, sshKeys.Select(SshKeyMeta.From));
            PasskeyMeta.Save(_acc.PasskeyMetaPath, passkeys.Select(PasskeyMeta.From));
        }
    }

    private void SaveState(string email, KdfConfig kdf, string userKeyEnc, string? privKeyEnc)
    {
        var state = PersistedSession.Load(_statePath) ?? new PersistedSession();
        state.Kdf = (int)kdf.Type;
        state.KdfIterations = kdf.Iterations;
        state.KdfMemory = kdf.MemoryMiB;
        state.KdfParallelism = kdf.Parallelism;
        state.ProtectedUserKey = userKeyEnc;
        state.ProtectedPrivateKey = privKeyEnc;
        state.Email = email;
        state.ServerUrl = _acc.ServerUrl;
        state.DeviceIdentifier = _deviceId;
        state.RefreshToken = _refreshToken;
        state.Save(_statePath);
    }

    private async Task EnsureAccessTokenAsync(CancellationToken ct)
    {
        if (_accessToken != null && DateTimeOffset.UtcNow < _accessExpiry) return;
        if (!await RefreshAccessTokenAsync(ct).ConfigureAwait(false))
            throw new InvalidOperationException("Session expired - please sign in again.");
    }

    private async Task<bool> RefreshAccessTokenAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_refreshToken)) return false;
        try
        {
            var (token, _, ok) = await Api().TokenRefreshAsync(_refreshToken, ct).ConfigureAwait(false);
            if (!ok || token.AccessToken == null) return false;
            _accessToken = token.AccessToken;
            _accessExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, token.ExpiresIn) - 60);
            if (!string.IsNullOrEmpty(token.RefreshToken) && token.RefreshToken != _refreshToken)
            {
                _refreshToken = token.RefreshToken;
                var state = PersistedSession.Load(_statePath);
                if (state != null) { state.RefreshToken = _refreshToken; state.Save(_statePath); }
            }
            return true;
        }
        catch (HttpRequestException) { return false; }
    }

    private static KdfConfig ToKdf(PreloginResponse pre)
        => pre.Kdf == 1
            ? KdfConfig.Argon2(pre.KdfIterations, pre.KdfMemory ?? 64, pre.KdfParallelism ?? 4)
            : KdfConfig.Pbkdf2(pre.KdfIterations);

    public void Dispose()
    {
        _crypto?.Dispose();
        Protector?.Dispose();
        _api?.Dispose();
    }
}
