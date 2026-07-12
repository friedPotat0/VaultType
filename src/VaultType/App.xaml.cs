using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using VaultType.Config;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;
using VaultType.Views;
using Drawing = System.Drawing;
using WinForms = System.Windows.Forms;

namespace VaultType;

public partial class App : Application
{
    private AppConfig _cfg = null!;
    private BitwardenCli _cli = null!;
    private IconService _icons = null!;
    private HotkeyManager _hotkey = null!;
    private IdleLockService _idle = null!;
    private ForegroundTracker? _fgTracker;
    private WinForms.NotifyIcon _tray = null!;
    private WinForms.ToolStripMenuItem? _statusItem, _lockItem, _syncItem;
    private Mutex? _mutex;

    // Session state (RAM only)
    private bool _unlocked;
    private SecureString? _session;
    private SecretProtector? _protector;
    private List<VaultItem> _items = new();
    private bool _busy;
    private bool _serverConfigured;
    private bool _cliVerified;    // bw.exe passed the Bitwarden-signature check (once per process)
    private Task? _serverReady;   // background CLI/Node warm-up so the unlock window can open instantly
    private string? _pendingUpdateUrl;   // set when a newer release is found; opened if the balloon is clicked

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Dev-only: render the real windows (with mock data) to PNGs for the README, then exit.
        for (int i = 0; i < e.Args.Length; i++)
        {
            if (string.Equals(e.Args[i], "--screenshots", StringComparison.OrdinalIgnoreCase))
            {
                string dir = i + 1 < e.Args.Length ? e.Args[i + 1]
                    : System.IO.Path.Combine(AppContext.BaseDirectory, "screenshots");
                RunScreenshotMode(dir);
                return;
            }
        }

        _mutex = new Mutex(true, "VaultType_SingleInstance_9F2A", out bool isNew);
        if (!isNew) { Shutdown(); return; }

        _cfg = AppConfig.Load();
        Loc.Init(_cfg.Language);
        ProcessHardening.Apply(_cfg.AntiDebugger);

        _cli = new BitwardenCli(_cfg);

        _hotkey = new HotkeyManager();
        _hotkey.Pressed += OnHotkey;
        bool hotkeyOk = _hotkey.Register(_cfg.Hotkey, out _);

        _idle = new IdleLockService(_cfg.IdleTimeoutMinutes);
        _idle.Lock += () => Dispatcher.Invoke(() => LockVault(true));

        _icons = new IconService(_cfg);
        if (_cfg.EnableTrayClick) _fgTracker = new ForegroundTracker();
        AutostartService.Set(_cfg.Autostart);   // keep the Run entry in sync with the preference

        SetupTray();
        if (hotkeyOk)
            ShowBalloon(Loc.T("msg.runningTitle"), Loc.T("msg.runningMsg", _cfg.Hotkey));
        else
            MessageBox.Show(Loc.T("msg.hotkeyInUse", _cfg.Hotkey), "VaultType",
                            MessageBoxButton.OK, MessageBoxImage.Warning);

        // First launch after install: start setup right away instead of idling in the tray.
        if (!_cfg.SignedInBefore)
            Dispatcher.BeginInvoke((Action)(() => _ = RunFirstTimeSetup()));
    }

    // Global hotkey: auto-type into the current foreground window (suggested entries first).
    private void OnHotkey() => _ = Trigger(ForegroundContext.CaptureWindow(), showAllFirst: false);

    // Tray click: auto-type into the window that was active before the click; list all entries.
    private void OnTrayTrigger()
    {
        IntPtr target = _fgTracker?.LastWindow ?? IntPtr.Zero;
        if (target == IntPtr.Zero) target = Native.GetForegroundWindow();
        _ = Trigger(ForegroundContext.FromWindow(target), showAllFirst: true);
    }

    // Shared flow (UI thread, async so slow work doesn't freeze the UI).
    private async Task Trigger(ForegroundInfo ctx, bool showAllFirst)
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var urlTask = Task.Run(() => ForegroundContext.ReadUrl(ctx.Hwnd, ctx.Exe)); // slow UIA in parallel

            if (!await EnsureCliReadyAsync()) return;
            BeginServerWarmup();   // cold-start bw.exe/Node in the background while the unlock window is up
            if (!_unlocked && !await EnsureUnlockedAsync()) return;

            // The URL read ran in parallel; only show a brief spinner if it isn't done yet.
            if (urlTask.IsCompleted) ctx.Url = await urlTask;
            else
            {
                var l = new LoadingWindow(_cfg.ExcludeFromScreenCapture);
                l.SetStatus(Loc.T("loading.reading"));
                l.Show();
                try { ctx.Url = await urlTask; } finally { l.Close(); }
            }

            var matches = Matcher.FindMatches(_items, ctx);
            var picker = new PickerWindow(_items, matches, ctx, _cfg.ExcludeFromScreenCapture, _icons, showAllFirst);
            bool? ok = picker.ShowDialog();
            _idle.Arm(_cfg.IdleTimeoutMinutes);

            if (ok == true && picker.Result != null)
            {
                Dispatch(picker.Result, ctx);
                MaybeOfferRemember(picker.Result.Item, matches, ctx);
            }
        }
        catch (Exception ex) { ShowBalloon("Error", ex.Message); }
        finally { _busy = false; }
    }

    // Drive the initial setup on the first launch: get the CLI in place, then sign in. No auto-type
    // target here - we just want the user set up and unlocked, ready for the next hotkey press.
    private async Task RunFirstTimeSetup()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            if (!await EnsureCliReadyAsync()) return;
            BeginServerWarmup();
            if (!_unlocked) await EnsureUnlockedAsync();
        }
        catch (Exception ex) { ShowBalloon("Error", ex.Message); }
        finally { _busy = false; }
    }

    // if they picked an entry we didn't auto-suggest, offer to remember it for next time
    private void MaybeOfferRemember(VaultItem item, IReadOnlyList<VaultItem> matches, ForegroundInfo ctx)
    {
        if (_session == null || matches.Contains(item)) return;
        string? uri = BuildRememberUri(ctx);
        if (uri == null) return;
        if (item.Uris.Any(u => string.Equals(u.Value, uri, StringComparison.OrdinalIgnoreCase))) return;

        string label = !string.IsNullOrEmpty(ctx.Url) ? Matcher.HostDomain(ctx.Url!).domain : ctx.Exe;
        var confirm = new ConfirmWindow(Loc.T("confirm.rememberTitle"),
            Loc.T("confirm.rememberMsg", uri, item.Name, label),
            _cfg.ExcludeFromScreenCapture);
        if (confirm.ShowDialog() != true) return;

        if (_cli.AddUri(_session, item.Id, uri, out string err))
        {
            var iu = new ItemUri { Value = uri, MatchType = 0 };
            Matcher.FillHostDomain(iu);
            item.Uris.Add(iu);
            ShowBalloon(Loc.T("msg.savedTitle"), Loc.T("msg.savedMsg", item.Name, label));
        }
        else ShowBalloon(Loc.T("msg.error"), err);
    }

    private static string? BuildRememberUri(ForegroundInfo ctx)
    {
        if (!string.IsNullOrEmpty(ctx.Url))
        {
            var (host, domain) = Matcher.HostDomain(ctx.Url!);
            string d = string.IsNullOrEmpty(domain) ? host : domain;
            return string.IsNullOrEmpty(d) ? null : "https://" + d;
        }
        if (!string.IsNullOrEmpty(ctx.Exe)) return "app://" + ctx.Exe;
        return null;
    }

    private void Dispatch(PickResult r, ForegroundInfo ctx)
    {
        // Actions that reveal the password/TOTP require re-prompt if the entry demands it.
        bool sensitive = r.Action is PickAction.TypeFull or PickAction.TypePassword or PickAction.TypeTotp
            or PickAction.CopyPassword or PickAction.CopyTotp;
        if (sensitive && r.Item.Reprompt && _cfg.HonorMasterPasswordReprompt && !VerifyMasterPassword()) return;

        int secs = _cfg.ClipboardClearSeconds;
        switch (r.Action)
        {
            case PickAction.TypeFull:
                AutoTyper.Type(ctx.Hwnd, r.Item, _protector!, TypeAction.Full, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypeUsername:
                AutoTyper.Type(ctx.Hwnd, r.Item, _protector!, TypeAction.Username, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypePassword:
                AutoTyper.Type(ctx.Hwnd, r.Item, _protector!, TypeAction.Password, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypeTotp:
                AutoTyper.Type(ctx.Hwnd, r.Item, _protector!, TypeAction.Totp, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.CopyUsername:
                ClipboardService.CopyUsername(r.Item, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedUser", secs)); break;
            case PickAction.CopyPassword:
                ClipboardService.CopyPassword(r.Item, _protector!, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedPass", secs)); break;
            case PickAction.CopyTotp:
                ClipboardService.CopyTotp(r.Item, _protector!, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedTotp", secs)); break;
        }
    }

    private async Task<bool> EnsureCliReadyAsync()
    {
        // Already in place (from a previous run, or dropped next to the app): verify it once.
        if (_cli.ExeExists) return _cliVerified || ConfirmCliTrusted(downloaded: false);

        // First run: ask before reaching out to the network, so nothing happens behind the user's back.
        var setup = new CliSetupWindow(_cfg.ExcludeFromScreenCapture, _cli.ExePath, CliBootstrap.DownloadUrl);
        setup.ShowDialog();
        if (setup.Choice == CliSetupChoice.Cancel) return false;

        if (setup.Choice == CliSetupChoice.Manual)
        {
            try
            {
                // SelectedFile is set for a dragged file; null means it's already in the target folder.
                if (setup.SelectedFile != null)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_cli.ExePath)!);
                    File.Copy(setup.SelectedFile, _cli.ExePath, overwrite: true);
                }
            }
            catch { /* falls through to the missing-CLI message below */ }
        }
        else // download from the official source
        {
            using var cts = new CancellationTokenSource();
            // Not topmost, so a firewall's allow/block prompt can surface in front of it.
            var dl = new CliDownloadWindow(_cfg.ExcludeFromScreenCapture, CliBootstrap.DownloadUrl);
            dl.Cancelled += () => cts.Cancel();
            dl.Show();
            var progress = new Progress<CliBootstrap.DownloadProgress>(p => dl.Report(p.BytesRead, p.TotalBytes));
            try { await CliBootstrap.EnsureAsync(_cli.ExePath, progress, cts.Token); }
            finally { dl.Close(); }
        }

        if (!_cli.ExeExists)
        {
            MessageBox.Show(Loc.T("msg.cliMissing", _cli.ExePath), "VaultType",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        return ConfirmCliTrusted(downloaded: setup.Choice == CliSetupChoice.Download);
    }

    // Only run a bw.exe we can attribute to Bitwarden. A freshly downloaded file that fails the
    // check is treated as tampering and dropped; a user-provided one gets a clear warning so they
    // can decide (they put it there). Cached for the process - the file doesn't change at runtime.
    private bool ConfirmCliTrusted(bool downloaded)
    {
        if (CodeSignature.IsBitwardenTrusted(_cli.ExePath)) { _cliVerified = true; return true; }

        if (downloaded)
        {
            try { File.Delete(_cli.ExePath); } catch { }
            MessageBox.Show(Loc.T("msg.cliUntrusted"), "VaultType",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var warn = new ConfirmWindow(Loc.T("cli.untrustedTitle"), Loc.T("cli.untrustedBody"), _cfg.ExcludeFromScreenCapture);
        if (warn.ShowDialog() == true) { _cliVerified = true; return true; }
        return false;
    }

    // Apply the server config on a background thread. The first bw.exe call cold-starts Node
    // (~1-2s); doing it here instead of before the unlock window lets the window pop up instantly
    // and hides the cold-start behind the time the user spends typing.
    private void BeginServerWarmup()
    {
        if (_serverConfigured || string.IsNullOrWhiteSpace(_cfg.ServerUrl)) return;
        _serverReady ??= Task.Run(() =>
        {
            _cli.ConfigServer(_cfg.ServerUrl, out _);
            _serverConfigured = true;
        });
    }

    private async Task<bool> EnsureUnlockedAsync()
    {
        // Start in sign-in mode only if we've never signed in; otherwise take the fast "unlock"
        // path (no upfront `bw status` - that Node cold-start delayed the window ~2s; a failed
        // unlock falls back to sign-in anyway).
        bool loginMode = !_cfg.SignedInBefore && string.IsNullOrEmpty(_cfg.AccountEmail);
        string server = _cfg.ServerUrl;
        string emailPrefill = _cfg.AccountEmail;
        string? pendingError = null;

        while (true)
        {
            string heading = loginMode ? Loc.T("unlock.titleSignin") : Loc.T("unlock.titleUnlock");
            // In sign-in mode the server is an editable field, so it isn't repeated in the subtitle.
            string subtitle = loginMode
                ? ""
                : $"{(emailPrefill.Length > 0 ? emailPrefill + "\n" : "")}{server}";

            var win = new UnlockWindow(heading, subtitle, loginMode, emailPrefill, server, _cfg.ExcludeFromScreenCapture);
            if (pendingError != null)
            {
                string errCopy = pendingError;
                win.Loaded += (_, __) => win.ShowError(errCopy);
                pendingError = null;
            }
            bool? ok = win.ShowDialog();
            if (ok != true || win.Password == null) return false;

            SecureString master = win.Password;
            if (win.Email.Length > 0) emailPrefill = win.Email;

            // In sign-in mode the user may have set/changed the server URL right in the form.
            if (loginMode && !string.Equals(win.Server, _cfg.ServerUrl, StringComparison.OrdinalIgnoreCase))
            {
                _cfg.ServerUrl = win.Server;
                _cfg.Save();
                server = win.Server;
                _serverConfigured = false;
            }

            var loading = new LoadingWindow(_cfg.ExcludeFromScreenCapture);
            loading.SetStatus(loginMode ? Loc.T("loading.signingin") : Loc.T("loading.unlocking"));
            loading.Show();

            // KDF (Argon2) + Node startup run OFF the UI thread so the spinner animates.
            var (session, err) = await Task.Run(() =>
            {
                if (_serverReady != null) { try { _serverReady.Wait(); } catch { } }   // let any warm-up finish
                string e;
                SecureString? s;
                if (!loginMode) s = _cli.Unlock(master, out e);
                else
                {
                    // apply the server from the sign-in form (empty = bitwarden.com default)
                    _cli.ConfigServer(string.IsNullOrWhiteSpace(_cfg.ServerUrl) ? "https://bitwarden.com" : _cfg.ServerUrl, out _);
                    _serverConfigured = true;
                    if (win.UseApiKey) s = _cli.LoginApiKey(win.ClientId, win.ClientSecret!, out e) ? _cli.Unlock(master, out e) : null;
                    else s = _cli.Login(win.Email, master, win.TwoFactorCode, win.TwoFactorMethod, out e);
                }
                return (s, e);
            });
            master.Dispose();
            win.ClientSecret?.Dispose();

            if (session == null)
            {
                loading.Close();
                if (!loginMode && LooksUnauthenticated(err)) { loginMode = true; continue; } // not logged in -> sign-in form
                pendingError = err;
                continue;
            }

            if (loginMode && win.Email.Length > 0) _cfg.AccountEmail = win.Email;
            if (!_cfg.SignedInBefore) _cfg.SignedInBefore = true;
            _cfg.Save();   // persist SignedInBefore (and AccountEmail)

            _session = session;
            _protector = new SecretProtector();
            loading.SetStatus(Loc.T("loading.loading"));

            var (items, lerr) = await Task.Run(() =>
            {
                var it = _cli.ListItems(session, _protector, out string e);
                return (it, e);
            });
            loading.Close();

            _items = items;
            if (_items.Count == 0 && lerr.Length > 0)
                ShowBalloon(Loc.T("msg.note"), Loc.T("msg.couldNotLoad", lerr));

            _unlocked = true;
            _idle.Arm(_cfg.IdleTimeoutMinutes);
            UpdateTray();
            return true;
        }
    }

    private static bool LooksUnauthenticated(string err)
        => err.Contains("logged in", StringComparison.OrdinalIgnoreCase)
        || err.Contains("log in", StringComparison.OrdinalIgnoreCase);

    private bool VerifyMasterPassword()
    {
        var win = new UnlockWindow(Loc.T("unlock.confirmTitle"),
            Loc.T("unlock.confirmMsg"),
            false, "", "", _cfg.ExcludeFromScreenCapture);
        if (win.ShowDialog() != true || win.Password == null) return false;
        SecureString? s = _cli.Unlock(win.Password, out _);
        win.Password.Dispose();
        if (s == null) return false;
        s.Dispose();
        return true;
    }

    private void LockVault(bool notify)
    {
        ClipboardService.ClearNow();
        if (_session != null) { _cli.Lock(_session); _session.Dispose(); _session = null; }
        _protector?.Dispose(); _protector = null;
        _items = new List<VaultItem>();
        _unlocked = false;
        _idle.Disarm();
        UpdateTray();
        if (notify) ShowBalloon(Loc.T("msg.lockedTitle"), Loc.T("msg.lockedMsg"));
    }

    private async void SyncNow()
    {
        if (!_unlocked || _session == null) { ShowBalloon(Loc.T("msg.note"), Loc.T("msg.unlockFirst")); return; }
        if (_busy) return;
        _busy = true;
        _idle.Disarm();   // don't let the idle-lock dispose the session while the sync runs off-thread
        try
        {
            var session = _session;
            var protector = _protector!;
            var (items, err) = await Task.Run(() =>
            {
                _cli.Sync(session);
                var it = _cli.ListItems(session, protector, out string e);
                return (it, e);
            });
            if (err.Length == 0) { _items = items; UpdateTray(); ShowBalloon(Loc.T("msg.syncedTitle"), Loc.T("msg.syncedMsg", _items.Count)); }
            else ShowBalloon(Loc.T("msg.syncErr"), err);
        }
        catch (Exception ex) { ShowBalloon(Loc.T("msg.syncErr"), ex.Message); }
        finally { _busy = false; if (_unlocked) _idle.Arm(_cfg.IdleTimeoutMinutes); }
    }

    private void OpenSettings()
    {
        _hotkey.Unregister();                 // don't let the global hotkey fire while it is being edited
        string prevLang = _cfg.Language;
        string prevHotkey = _cfg.Hotkey;
        bool langChanged = false;
        bool changeLogin = false;
        bool hotkeyFailed = false;
        try
        {
            var w = new SettingsWindow(_cfg, _cfg.ExcludeFromScreenCapture);
            if (w.ShowDialog() != true) return;
            _cfg.Save();
            if (_cfg.EnableTrayClick && _fgTracker == null) _fgTracker = new ForegroundTracker();
            else if (!_cfg.EnableTrayClick && _fgTracker != null) { _fgTracker.Dispose(); _fgTracker = null; }
            _serverConfigured = false;        // re-apply server config on next unlock if the URL changed
            _serverReady = null;              // force a fresh warm-up with the (possibly) new URL
            if (_unlocked) _idle.Arm(_cfg.IdleTimeoutMinutes);
            UpdateTray();
            langChanged = !string.Equals(prevLang, _cfg.Language, StringComparison.OrdinalIgnoreCase);
            changeLogin = w.ChangeLoginRequested;
        }
        finally
        {
            hotkeyFailed = !_hotkey.Register(_cfg.Hotkey, out _);   // re-register: new combo if saved, old if cancelled
        }

        // Only warn when the user actually picked a new combo that another program already holds.
        if (hotkeyFailed && !string.Equals(prevHotkey, _cfg.Hotkey, StringComparison.OrdinalIgnoreCase))
            MessageBox.Show(Loc.T("msg.hotkeyInUse", _cfg.Hotkey), "VaultType",
                            MessageBoxButton.OK, MessageBoxImage.Warning);

        // The UI resolves its strings once at startup, so a language switch needs a fresh process.
        if (langChanged) { RestartApp(); return; }
        if (changeLogin) ChangeLogin();
    }

    // Log out and reopen the sign-in window so the user can switch account, server or email/API key.
    private async void ChangeLogin()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            if (!await EnsureCliReadyAsync()) return;
            LockVault(false);                        // drop the current in-app session
            await Task.Run(() => _cli.Logout());     // bw logout so a different account can sign in
            _cfg.SignedInBefore = false;
            _cfg.AccountEmail = "";
            _cfg.Save();
            _serverConfigured = false;
            _serverReady = null;
            await EnsureUnlockedAsync();              // starts in sign-in mode
        }
        catch (Exception ex) { ShowBalloon(Loc.T("msg.error"), ex.Message); }
        finally { _busy = false; }
    }

    private void RestartApp()
    {
        string? exe = Environment.ProcessPath;
        // Release the single-instance mutex first so the new process can claim it.
        try { _mutex?.ReleaseMutex(); } catch { }
        try { _mutex?.Dispose(); } catch { }
        _mutex = null;
        if (exe != null)
        {
            try { Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true }); } catch { }
        }
        ExitApp();
    }

    // Manual update check from the tray menu. On success the balloon is clickable and opens the release.
    private async void CheckForUpdates()
    {
        var info = await UpdateService.CheckAsync(AppInfo.Version);
        if (info == null) { ShowBalloon(Loc.T("msg.error"), Loc.T("msg.updateFailed")); return; }
        if (info.IsNewer)
        {
            _pendingUpdateUrl = info.Url;
            ShowBalloon(Loc.T("msg.updateTitle"), Loc.T("msg.updateAvailable", info.LatestVersion));
        }
        else
        {
            _pendingUpdateUrl = null;
            ShowBalloon("VaultType", Loc.T("msg.upToDate", AppInfo.Version));
        }
    }

    // ---- Screenshot mode (README assets) ----

    // Render the app's windows to transparent PNGs with mock data, then quit.
    private void RunScreenshotMode(string outDir)
    {
        try
        {
            Loc.Init("en");
            try { System.IO.Directory.CreateDirectory(outDir); } catch { }

            _cfg = new AppConfig
            {
                ServerUrl = "https://vault.example.com",
                ShowIcons = false,   // offline capture: letter avatars, no network requests
            };

            var icons = new IconService(_cfg);
            var ctx = new ForegroundInfo { Exe = "brave.exe", Title = "Sign in to GitHub", Url = "https://github.com/login" };
            var all = BuildMockItems();

            var picker = new PickerWindow(all, all, ctx, false, icons, showAllFirst: true);
            CaptureWindow(picker, System.IO.Path.Combine(outDir, "picker.png"));

            var signinVw = new UnlockWindow("Sign in", "", true, "", "https://vault.example.net", false);
            signinVw.EmailBox.Text = "alex.doe@example.com";
            signinVw.Pw.Password = "correct horse battery staple";
            CaptureWindow(signinVw, System.IO.Path.Combine(outDir, "signin-vaultwarden.png"),
                beforeRender: () => MoveCaretToEnd(signinVw.Pw));

            var signinBw = new UnlockWindow("Sign in", "", true, "", "", false);
            signinBw.AccountBox.SelectedIndex = 1;   // Bitwarden.com -> API-key login by default
            signinBw.ClientIdBox.Text = "user.7f3a1c9e-2b4d-4e8a-9f10-abcdef123456";
            signinBw.ClientSecretBox.Password = "aXb9Kd2mNp7qRs4tUv1wYz0e";
            signinBw.Pw.Password = "correct horse battery staple";
            CaptureWindow(signinBw, System.IO.Path.Combine(outDir, "signin-bitwarden.png"),
                beforeRender: () => MoveCaretToEnd(signinBw.Pw));

            var unlock = new UnlockWindow("Unlock vault",
                "alex.doe@example.com\nhttps://vault.example.com", false, "", "", false);
            unlock.Pw.Password = "correct horse battery staple";
            CaptureWindow(unlock, System.IO.Path.Combine(outDir, "unlock.png"),
                beforeRender: () => MoveCaretToEnd(unlock.Pw));

            var settings = new SettingsWindow(_cfg, false);
            CaptureWindow(settings, System.IO.Path.Combine(outDir, "settings.png"));

            var cliSetup = new CliSetupWindow(false,
                @"C:\Users\alex\AppData\Local\VaultType\bw.exe", CliBootstrap.DownloadUrl);
            CaptureWindow(cliSetup, System.IO.Path.Combine(outDir, "cli-setup.png"));

            var cliDownload = new CliDownloadWindow(false, CliBootstrap.DownloadUrl);
            cliDownload.Preview(12_600_000, 30_100_000, 3_300_000);   // ~42 %, 3.3 MB/s
            CaptureWindow(cliDownload, System.IO.Path.Combine(outDir, "cli-download.png"));
        }
        catch (Exception ex) { MessageBox.Show(ex.ToString(), "Screenshot mode"); }
        finally { Shutdown(); }
    }

    // Mock login entries - display data only, no real secrets - covering every badge state.
    private static List<VaultItem> BuildMockItems()
    {
        static VaultItem It(string name, string user, string host, bool totp = false, string? seq = null)
        {
            var it = new VaultItem { Name = name, Username = user, HasTotp = totp, CustomSequence = seq };
            if (host.Length > 0) it.Uris.Add(new ItemUri { Value = "https://" + host, Host = host, Domain = host });
            return it;
        }
        return new List<VaultItem>
        {
            It("GitHub", "alex.doe@example.com", "github.com", totp: true),
            It("Google", "alex.doe@example.com", "google.com", totp: true),
            It("Amazon AWS", "iam-admin", "aws.amazon.com", seq: "{USERNAME}{TAB}{PASSWORD}{ENTER}"),
            It("Proxmox VE", "root@pam", "pve.example.lan", seq: "{USERNAME}{TAB}{PASSWORD}{ENTER}"),
            It("Nextcloud", "alex.doe", "cloud.example.com"),
            It("Reddit", "u/night_owl", "reddit.com", totp: true),
            It("Steam", "night_owl", "steampowered.com", totp: true, seq: "{USERNAME}{TAB}{PASSWORD}{ENTER}"),
            It("PayPal", "alex.doe@example.com", "paypal.com"),
        };
    }

    // Show a window off-screen, let it lay out, then render it (2x, transparent) to a PNG.
    private void CaptureWindow(Window w, string path, double scale = 2.0, Action? beforeRender = null)
    {
        w.WindowStartupLocation = WindowStartupLocation.Manual;
        w.Left = -10000;
        w.Top = -10000;
        w.ShowInTaskbar = false;
        w.Topmost = false;
        w.Show();

        // Let Loaded handlers, layout and a render pass finish before capturing.
        Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
        w.UpdateLayout();
        Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
        w.UpdateLayout();

        beforeRender?.Invoke();
        Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
        w.UpdateLayout();

        var root = (FrameworkElement)w.Content;   // root Border (Margin=16) incl. its drop shadow
        double width = w.ActualWidth;
        double height = w.ActualHeight;

        var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(
            (int)System.Math.Ceiling(width * scale),
            (int)System.Math.Ceiling(height * scale),
            96 * scale, 96 * scale,
            System.Windows.Media.PixelFormats.Pbgra32);
        rtb.Render(root);

        var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
        enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
        using (var fs = System.IO.File.Create(path)) enc.Save(fs);

        w.Close();
    }

    // put the password caret at the end (after the dots), like a normally filled field
    private static void MoveCaretToEnd(System.Windows.Controls.PasswordBox pw)
    {
        pw.Focus();
        try
        {
            typeof(System.Windows.Controls.PasswordBox)
                .GetMethod("Select", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?.Invoke(pw, new object[] { pw.Password.Length, 0 });
        }
        catch { }
    }

    // ---- Tray ----
    private void SetupTray()
    {
        _tray = new WinForms.NotifyIcon { Icon = BuildIcon(), Visible = true, Text = $"VaultType {AppInfo.Version}" };
        var menu = new WinForms.ContextMenuStrip();
        _statusItem = new WinForms.ToolStripMenuItem(Loc.T("tray.locked")) { Enabled = false };
        menu.Items.Add(_statusItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(Loc.T("tray.autotype"), null, (_, __) => OnHotkey());
        _syncItem = new WinForms.ToolStripMenuItem(Loc.T("tray.sync"), null, (_, __) => SyncNow());
        menu.Items.Add(_syncItem);
        _lockItem = new WinForms.ToolStripMenuItem(Loc.T("tray.lock"), null, (_, __) => LockVault(true));
        menu.Items.Add(_lockItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(Loc.T("tray.checkUpdates"), null, (_, __) => CheckForUpdates());
        menu.Items.Add(Loc.T("tray.settings"), null, (_, __) => OpenSettings());
        menu.Items.Add(Loc.T("tray.exit"), null, (_, __) => ExitApp());
        _tray.ContextMenuStrip = menu;
        _tray.MouseClick += (_, e) => { if (_cfg.EnableTrayClick && e.Button == WinForms.MouseButtons.Left) OnTrayTrigger(); };
        _tray.BalloonTipClicked += (_, __) =>
        {
            if (_pendingUpdateUrl == null) return;
            try { Process.Start(new ProcessStartInfo(_pendingUpdateUrl) { UseShellExecute = true }); } catch { }
            _pendingUpdateUrl = null;
        };
        UpdateTray();
    }

    private void UpdateTray()
    {
        if (_statusItem != null) _statusItem.Text = _unlocked ? Loc.T("tray.unlocked", _items.Count) : Loc.T("tray.locked");
        if (_lockItem != null) _lockItem.Enabled = _unlocked;
    }

    private static Drawing.Icon BuildIcon()
    {
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var s = asm.GetManifestResourceStream("VaultType.Assets.vaulttype.ico");
            if (s != null) return new Drawing.Icon(s, new Drawing.Size(32, 32));
        }
        catch { }

        // Fallback: plain green rounded square
        using var bmp = new Drawing.Bitmap(32, 32);
        using (var g = Drawing.Graphics.FromImage(bmp))
        {
            g.SmoothingMode = Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Drawing.Color.Transparent);
            using var path = RoundedRect(3f, 3f, 26f, 26f, 7f);
            using var green = new Drawing.SolidBrush(Drawing.ColorTranslator.FromHtml("#3FAE77"));
            g.FillPath(green, path);
        }
        return Drawing.Icon.FromHandle(bmp.GetHicon());
    }

    private static Drawing.Drawing2D.GraphicsPath RoundedRect(float x, float y, float w, float h, float r)
    {
        var p = new Drawing.Drawing2D.GraphicsPath();
        p.AddArc(x, y, r, r, 180, 90);
        p.AddArc(x + w - r, y, r, r, 270, 90);
        p.AddArc(x + w - r, y + h - r, r, r, 0, 90);
        p.AddArc(x, y + h - r, r, r, 90, 90);
        p.CloseFigure();
        return p;
    }

    private void ShowBalloon(string title, string text)
    {
        try { _tray.BalloonTipTitle = title; _tray.BalloonTipText = text; _tray.ShowBalloonTip(4000); }
        catch { }
    }

    private void ExitApp()
    {
        LockVault(false);
        try { _tray.Visible = false; _tray.Dispose(); } catch { }
        _hotkey?.Dispose();
        _idle?.Dispose();
        _fgTracker?.Dispose();
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _mutex?.ReleaseMutex(); _mutex?.Dispose(); } catch { }
        base.OnExit(e);
    }
}
