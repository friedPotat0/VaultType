using System.Windows.Threading;
using VaultType.Services;
using VaultType.Vault;
using VaultType.Views;

namespace VaultType;

// Web vault and the read-only vault view.
//
// "Open web vault" opens the account's own web vault in the browser and then, for a few minutes,
// watches for a "log in with device" request from it. The request is shown with its fingerprint
// phrase; only an explicit approval sends the user key, encrypted to that browser. Nothing is
// polled unless the user just opened the web vault from here.
public partial class App
{
    // How long after "Open web vault" requests are looked for, and how often.
    private static readonly TimeSpan LoginWatchDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan LoginPollInterval = TimeSpan.FromSeconds(4);

    // Account id -> (requests created since, watch ends at).
    private readonly Dictionary<string, (DateTimeOffset Since, DateTimeOffset Until)> _loginWatch = new();
    // Requests already shown (or skipped) - each is offered once.
    private readonly HashSet<string> _seenLoginRequests = new();
    private DispatcherTimer? _loginPoll;
    private bool _loginPolling, _loginDialogOpen;

    private VaultViewWindow? _vaultView;

    public static string WebVaultUrl(VaultSession s)
        => string.IsNullOrWhiteSpace(s.Cfg.ServerUrl) ? Config.AccountConfig.UsCloud : s.Cfg.ServerUrl.TrimEnd('/');

    private void OpenWebVault(VaultSession s)
    {
        // Only ever hand a plain web address to the shell, whatever ended up in the config.
        if (!Uri.TryCreate(WebVaultUrl(s), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            ShowError(Loc.T("webVault.badUrl"));
            return;
        }
        OpenUrl(uri.AbsoluteUri);

        // Requests from just before the click count too (clock skew between PC and server).
        var now = DateTimeOffset.UtcNow;
        var since = _loginWatch.TryGetValue(s.Cfg.Id, out var w) && w.Until > now ? w.Since : now - TimeSpan.FromMinutes(1);
        _loginWatch[s.Cfg.Id] = (since, now + LoginWatchDuration);
        if (_loginPoll == null)
        {
            _loginPoll = new DispatcherTimer { Interval = LoginPollInterval };
            _loginPoll.Tick += (_, _) => _ = PollLoginRequestsAsync();
        }
        _loginPoll.Start();
    }

    private async Task PollLoginRequestsAsync()
    {
        if (_loginPolling || _loginDialogOpen) return;
        var now = DateTimeOffset.UtcNow;
        foreach (var expired in _loginWatch.Where(kv => kv.Value.Until <= now).Select(kv => kv.Key).ToList())
            _loginWatch.Remove(expired);
        if (_loginWatch.Count == 0) { _loginPoll?.Stop(); return; }

        _loginPolling = true;
        try
        {
            foreach (var (accountId, watch) in _loginWatch.ToList())
            {
                var s = _sessions.FirstOrDefault(x => x.Cfg.Id == accountId);
                if (s == null) { _loginWatch.Remove(accountId); continue; }

                List<LoginRequest> pending;
                try { pending = await Task.Run(() => s.Backend.PendingLoginRequestsAsync(watch.Since)); }
                catch { continue; }   // offline, signed out or a hiccup: the next tick tries again

                foreach (var r in pending.Where(r => _seenLoginRequests.Add(r.Id)).OrderBy(r => r.Created))
                {
                    _loginDialogOpen = true;
                    try { await AnswerLoginRequestAsync(s, r); }
                    finally { _loginDialogOpen = false; }
                }
            }
        }
        finally { _loginPolling = false; }
    }

    private async Task AnswerLoginRequestAsync(VaultSession s, LoginRequest r)
    {
        // Approving sends the user key, so the vault has to be open - just like the official apps,
        // which only show the request once unlocked.
        if (!s.Unlocked && !UnlockForAgent(s, out _, "webVault.unlockFor")) return;
        if (s.Backend.IsOffline) return;

        string where = string.Join(" ", new[] { r.Country, r.IpAddress.Length > 0 ? $"({r.IpAddress})" : "" }.Where(p => p.Length > 0));
        var minutes = (int)Math.Max(0, (DateTimeOffset.UtcNow - r.Created).TotalMinutes);
        string when = minutes < 1 ? Loc.T("webVault.justNow") : Loc.T("webVault.minutesAgo", minutes);
        string message = Loc.T("webVault.approveMsg", s.Cfg.Name, s.Cfg.AccountEmail,
            r.DeviceType.Length > 0 ? r.DeviceType : "?", where.Length > 0 ? where : "?", when);

        var dlg = new ConfirmWindow(Loc.T("webVault.approveTitle"), message, _cfg.ExcludeFromScreenCapture,
            confirmText: Loc.T("webVault.approve"), cancelText: Loc.T("webVault.deny"),
            highlight: r.Fingerprint, focusCancel: true);
        bool approve = dlg.ShowDialog() == true;

        try
        {
            // Approve and deny need no confirmation; a request that could no longer be answered does.
            var result = await Task.Run(() => s.Backend.AnswerLoginRequestAsync(r, approve));
            if (result == LoginAnswerResult.Approved) _loginWatch.Remove(s.Cfg.Id);   // done: stop looking
            else if (result == LoginAnswerResult.NoLongerValid)
                ShowError(Loc.T("webVault.expiredMsg"), Loc.T("webVault.expiredTitle"));
        }
        catch (ServerUnreachableException) { ShowError(Loc.T("unlock.errUnreachable")); }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    private void StopLoginWatch()
    {
        _loginWatch.Clear();
        _loginPoll?.Stop();
    }

    // ---- read-only vault view ----

    private async void OpenVaultView()
    {
        if (_vaultView != null) { _vaultView.Activate(); return; }
        if (_busy) return;
        if (!AnyUnlocked)
        {
            if (_cfg.Accounts.Count == 0) return;
            _busy = true;
            try { if (!await UnlockSessionAsync(MostRecentlyUnlocked())) return; }
            finally { _busy = false; }
        }

        _vaultView = new VaultViewWindow(_sessions, _cfg, VerifyMasterPassword, UnlockFromVaultView);
        _vaultView.Closed += (_, _) => _vaultView = null;
        _vaultView.Show();
    }

    // A locked vault's section in the view was clicked. UpdateTray refreshes the view afterwards.
    private async Task UnlockFromVaultView(VaultSession s)
    {
        if (_busy || s.Unlocked) return;
        _busy = true;
        try { await UnlockSessionAsync(s); }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { _busy = false; }
    }

    // Locking takes the view down with it; a sync or the switch back online refreshes it.
    private void CloseVaultViewIfLocked()
    {
        if (_vaultView == null) return;
        if (AnyUnlocked) _vaultView.Reload();
        else _vaultView.Close();
    }
}
