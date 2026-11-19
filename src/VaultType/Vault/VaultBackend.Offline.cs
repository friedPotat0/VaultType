using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using VaultType.Models;
using VaultType.Services;
using VaultType.Vault.Models;

namespace VaultType.Vault;

public enum UriSaveResult { Saved, Queued }

// Raised by every server write while the vault is open from the offline copy.
public sealed class VaultOfflineException : InvalidOperationException
{
    public VaultOfflineException() : base(Loc.T("offline.readOnly")) { }
}

// Offline side of the backend: website/app bindings remembered while the server can't be reached
// (queued, sealed with the user key, sent once it's back), and the read-only offline copy of the
// vault (see OfflineCopy) that lets the vault open without the server.
public sealed partial class VaultBackend
{
    // True while the vault was opened from the offline copy. Everything is read-only then; the
    // app keeps trying to reach the server (TryGoOnlineAsync) and switches over once it can.
    public bool IsOffline { get; private set; }

    // When the offline copy currently open (or last written) was taken from the server.
    public DateTimeOffset? OfflineCopySavedUtc { get; private set; }

    // The last error writing the offline copy, null after a successful write. Shown once by the app
    // so a copy that silently stopped updating doesn't go unnoticed.
    public string? OfflineCopyError { get; private set; }

    private string OfflineCopyPath => OfflineCopy.PathFor(_app.OfflineCopyFolder, _acc.Id, _acc.DataDir);

    // ---- pending website/app bindings ----

    private sealed class PendingUri
    {
        public string ItemId { get; set; } = "";
        public string Uri { get; set; } = "";
    }

    private string PendingPath => Path.Combine(_acc.DataDir, "pending-uris.json");
    private readonly object _pendingGate = new();
    private List<PendingUri>? _pending;   // null until loaded for the current unlock
    private readonly SemaphoreSlim _flushGate = new(1, 1);

    public int PendingCount
    {
        get { lock (_pendingGate) return EnsurePendingLoaded().Count; }
    }

    // Remember a website/app for a login. Sent to the server right away when it is reachable;
    // otherwise queued (sealed with the user key) and sent by FlushPendingAsync later.
    public async Task<UriSaveResult> AddUriAsync(string itemId, string uri, CancellationToken ct = default)
    {
        if (!Unlocked || _crypto == null) throw new InvalidOperationException("Account is locked.");
        if (!IsOffline)
        {
            var cipher = _ciphers.FirstOrDefault(c => c.Id == itemId)
                ?? throw new InvalidOperationException("The entry no longer exists.");
            try
            {
                await PutUriAsync(cipher, uri, ct).ConfigureAwait(false);
            }
            catch (ServerUnreachableException)
            {
                Enqueue(itemId, uri);
                return UriSaveResult.Queued;
            }
            try { await SyncAsync(ct).ConfigureAwait(false); }
            catch (ServerUnreachableException) { /* saved; the next sync picks it up */ }
            return UriSaveResult.Saved;
        }
        Enqueue(itemId, uri);
        return UriSaveResult.Queued;
    }

    private async Task PutUriAsync(CipherModel cipher, string uri, CancellationToken ct)
    {
        await EnsureAccessTokenAsync(ct).ConfigureAwait(false);
        string body = CipherJson.BuildAddUriBody(cipher, _crypto!.EncryptForCipher(cipher, uri),
            _crypto.EncryptForCipher(cipher, AccountCrypto.UriChecksum(uri)), _userId);
        await Api().PutCipherAsync(_accessToken!, cipher.Id!, body, ct).ConfigureAwait(false);
    }

    private void Enqueue(string itemId, string uri)
    {
        lock (_pendingGate)
        {
            var list = EnsurePendingLoaded();
            if (!list.Any(p => p.ItemId == itemId && string.Equals(p.Uri, uri, StringComparison.OrdinalIgnoreCase)))
                list.Add(new PendingUri { ItemId = itemId, Uri = uri });
            SavePending(list);
        }
        // Make the binding effective locally at once, so the entry matches from now on.
        lock (_decryptGate)
        {
            var item = Items.FirstOrDefault(i => i.Id == itemId);
            if (item != null) AddLocalUri(item, uri);
        }
    }

    // Send every queued binding. Each one is applied to the entry as the server has it now (read,
    // add the URI, write back), followed by a sync, so changes made elsewhere meanwhile are kept.
    // Returns how many were sent; stops quietly when the server is still unreachable.
    public async Task<int> FlushPendingAsync(CancellationToken ct = default)
    {
        if (IsOffline || !Unlocked || PendingCount == 0) return 0;
        if (!await _flushGate.WaitAsync(0, ct).ConfigureAwait(false)) return 0;
        int applied = 0;
        try
        {
            while (true)
            {
                PendingUri? next;
                lock (_pendingGate) next = EnsurePendingLoaded().FirstOrDefault();
                if (next == null || IsOffline || !Unlocked) break;

                var cipher = _ciphers.FirstOrDefault(c => c.Id == next.ItemId);
                if (cipher != null && cipher.DeletedDate == null)
                {
                    try
                    {
                        await PutUriAsync(cipher, next.Uri, ct).ConfigureAwait(false);
                        applied++;
                    }
                    catch (ServerUnreachableException) { break; }
                    catch (HttpRequestException) { /* the server refused it; don't retry forever */ }
                }
                Dequeue(next);
                // Fresh ciphers before the next binding: it may target the same entry.
                if (applied > 0) await SyncCoreAsync(ct).ConfigureAwait(false);
            }
        }
        finally { _flushGate.Release(); }
        return applied;
    }

    private void Dequeue(PendingUri p)
    {
        lock (_pendingGate)
        {
            var list = EnsurePendingLoaded();
            if (list.Remove(p)) SavePending(list);
        }
    }

    // Called from DecryptAll with the freshly decrypted items: re-apply queued bindings locally and
    // drop the ones the server already has (or whose entry is gone for good).
    private void OverlayPending(List<VaultItem> items, List<CipherModel> ciphers)
    {
        lock (_pendingGate)
        {
            var list = EnsurePendingLoaded();
            if (list.Count == 0) return;
            bool changed = false;
            foreach (var p in list.ToList())
            {
                var item = items.FirstOrDefault(i => i.Id == p.ItemId);
                if (item == null)
                {
                    // Entry deleted or trashed on the server: nothing left to attach the URI to.
                    if (!IsOffline && !ciphers.Any(c => c.Id == p.ItemId && c.DeletedDate == null))
                    { list.Remove(p); changed = true; }
                    continue;
                }
                if (!IsOffline && item.Uris.Any(u => string.Equals(u.Value, p.Uri, StringComparison.OrdinalIgnoreCase)))
                { list.Remove(p); changed = true; continue; }
                AddLocalUri(item, p.Uri);
            }
            if (changed) SavePending(list);
        }
    }

    private static void AddLocalUri(VaultItem item, string uri)
    {
        if (item.Uris.Any(u => string.Equals(u.Value, uri, StringComparison.OrdinalIgnoreCase))) return;
        var iu = new ItemUri { Value = uri };   // no explicit match -> follows the configured default
        Matcher.FillHostDomain(iu);
        item.Uris.Add(iu);
    }

    // Caller holds _pendingGate. The queue file is sealed with the user key, so it can only be read
    // while the vault is unlocked; it reveals neither the URIs nor which entries they belong to.
    private List<PendingUri> EnsurePendingLoaded()
    {
        if (_pending != null) return _pending;
        if (_crypto?.IsUnlocked != true) return new List<PendingUri>();
        var list = new List<PendingUri>();
        try
        {
            if (File.Exists(PendingPath))
                list = JsonSerializer.Deserialize<List<PendingUri>>(_crypto.DecryptWithUserKey(File.ReadAllText(PendingPath))) ?? new();
        }
        catch { /* unreadable (e.g. sealed with a rotated key): start over */ }
        _pending = list;
        return list;
    }

    private void SavePending(List<PendingUri> list)
    {
        try
        {
            if (list.Count == 0) { if (File.Exists(PendingPath)) File.Delete(PendingPath); return; }
            if (_crypto?.IsUnlocked != true) return;
            Directory.CreateDirectory(_acc.DataDir);
            string tmp = PendingPath + ".tmp";
            File.WriteAllText(tmp, _crypto.EncryptWithUserKey(JsonSerializer.Serialize(list)));
            File.Move(tmp, PendingPath, overwrite: true);
        }
        catch { /* the queue stays in RAM for this session */ }
    }

    // ---- offline copy ----

    // Replace the offline copy with the vault as just received from the server.
    private void SaveOfflineCopy(string rawSync)
    {
        if (!_acc.OfflineCopy || _mockUnlocked || IsOffline || _crypto?.IsUnlocked != true) return;
        try
        {
            var now = DateTimeOffset.UtcNow;
            OfflineCopy.Write(OfflineCopyPath, new OfflineCopy.Document
            {
                AccountId = _acc.Id,
                SavedUtc = now,
                Payload = _crypto.EncryptWithUserKey(rawSync),
            });
            OfflineCopySavedUtc = now;
            OfflineCopyError = null;
        }
        catch (Exception ex) { OfflineCopyError = ex.Message; }
    }

    public void DeleteOfflineCopy() => OfflineCopy.Delete(OfflineCopyPath);

    // The server is unreachable but the user key is already unwrapped into _crypto (master password
    // or PIN was right): open the vault read-only from the offline copy instead. False when the
    // feature is off or there is no usable copy for this account.
    private bool TryOpenOfflineCopy(string? protectedPrivateKey)
    {
        if (!_acc.OfflineCopy || _crypto?.IsUnlocked != true) return false;
        var doc = OfflineCopy.Read(OfflineCopyPath, _acc.Id);
        if (doc == null) return false;
        try
        {
            var sync = VaultApiClient.ParseSync(_crypto.DecryptWithUserKey(doc.Payload));
            // Unlock again with the copy's profile, so organization entries decrypt as well.
            var crypto = new AccountCrypto();
            crypto.UnlockWithUserKeyRaw(_crypto.ExportUserKeyRaw(),
                sync.Profile?.PrivateKey ?? protectedPrivateKey, sync.Profile?.Organizations ?? new());
            lock (_decryptGate)
            {
                _crypto.Dispose();
                _crypto = crypto;
                IsOffline = true;
            }
            DecryptAll(sync, fromServer: false);
            OfflineCopySavedUtc = doc.SavedUtc;
            return true;
        }
        catch
        {
            // Unreadable copy (sealed with a rotated key, damaged): behave as if there were none.
            return false;
        }
    }

    // While open from the offline copy: reach the server, sync and switch to normal (writable)
    // operation, then send queued bindings. False while still offline (or the stored session was
    // rejected, which needs a fresh sign-in after locking). Throws nothing for "still unreachable".
    private readonly SemaphoreSlim _onlineGate = new(1, 1);
    public async Task<bool> TryGoOnlineAsync(CancellationToken ct = default)
    {
        if (!IsOffline) return true;
        if (!await _onlineGate.WaitAsync(0, ct).ConfigureAwait(false)) return false;
        try
        {
            if (!IsOffline) return true;
            if (!Unlocked || _crypto == null) return false;
            if (!await RefreshAccessTokenAsync(ct).ConfigureAwait(false)) return false;
            var (sync, raw) = await Api().SyncAsync(_accessToken!, ct).ConfigureAwait(false);
            var state = PersistedSession.Load(_statePath);
            var crypto = new AccountCrypto();
            try
            {
                crypto.UnlockWithUserKeyRaw(_crypto.ExportUserKeyRaw(),
                    sync.Profile?.PrivateKey ?? state?.ProtectedPrivateKey, sync.Profile?.Organizations ?? new());
            }
            catch (CryptographicException) { crypto.Dispose(); return false; }   // keys rotated elsewhere
            lock (_decryptGate)
            {
                _crypto.Dispose();
                _crypto = crypto;
                IsOffline = false;
            }
            DecryptAll(sync);
            SaveOfflineCopy(raw);
            try { await FlushPendingAsync(ct).ConfigureAwait(false); } catch { /* retried with the next sync */ }
            return true;
        }
        catch (ServerUnreachableException) { ResetConnections(); return false; }
        catch (HttpRequestException) { return false; }
        finally { _onlineGate.Release(); }
    }
}
