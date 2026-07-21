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
using VaultType.Security.Passkey;
using VaultType.Services;
using VaultType.Vault;
using VaultType.Views;
using Drawing = System.Drawing;
using WinForms = System.Windows.Forms;

namespace VaultType;

public partial class App : Application
{
    private AppConfig _cfg = null!;
    private HotkeyManager _hotkey = null!;
    private IdleLockService _idle = null!;
    private ForegroundTracker? _fgTracker;
    private WinForms.NotifyIcon _tray = null!;
    private SshAgentService? _sshAgent;
    private PasskeyIpcServer? _passkeyIpc;
    private Mutex? _mutex;

    // One runtime session per configured account (RAM only). Several may be unlocked at once.
    private readonly List<VaultSession> _sessions = new();
    private bool _busy;
    private string? _pendingUpdateUrl;   // set when a newer release is found; opened if the balloon is clicked

    private bool AnyUnlocked => _sessions.Any(s => s.Unlocked);
    private int TotalItems => _sessions.Where(s => s.Unlocked).Sum(s => s.Items.Count);

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Windows launches "VaultType.exe -PluginActivated" (via the MSIX com:ExeServer) to serve the
        // passkey plugin COM object - NOT the normal tray app. Hand off to the passkey COM host.
        if (e.Args.Any(a => string.Equals(a, "-PluginActivated", StringComparison.OrdinalIgnoreCase)))
        {
            VaultType.Security.Passkey.PasskeyComHost.Run();
            Shutdown();
            return;
        }

        // Dev-only: run the crypto known-answer/round-trip self-test, write the report and exit.
        for (int i = 0; i < e.Args.Length; i++)
        {
            if (string.Equals(e.Args[i], "--cryptotest", StringComparison.OrdinalIgnoreCase))
            {
                string outPath = i + 1 < e.Args.Length ? e.Args[i + 1]
                    : System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vaulttype-cryptotest.txt");
                string report = VaultType.Vault.Crypto.CryptoSelfTest.Run();
                System.IO.File.WriteAllText(outPath, report);
                Shutdown();
                return;
            }
        }

        // Dev-only: run the full login+sync+decrypt pipeline against a real server. Reads
        // "server\nemail\npassword\n[2faProvider]\n[2faCode|newDeviceOtp]" from a file so secrets
        // stay off the command line. Writes the report and exits.
        for (int i = 0; i < e.Args.Length; i++)
        {
            if (string.Equals(e.Args[i], "--vaulttest", StringComparison.OrdinalIgnoreCase))
            {
                string inPath = e.Args[i + 1];
                string outPath = e.Args[i + 2];
                string report;
                try
                {
                    var lines = System.IO.File.ReadAllLines(inPath);
                    int? prov = lines.Length > 3 && int.TryParse(lines[3], out int p) ? p : null;
                    string? code = lines.Length > 4 ? lines[4] : null;
                    // Run off the UI thread: awaiting on the dispatcher thread and blocking on the
                    // result would deadlock (sync-over-async).
                    report = Task.Run(() => VaultType.Vault.VaultLiveTest
                        .RunAsync(lines[0].Trim(), lines[1].Trim(), lines[2], prov != null ? code : null, prov,
                                  prov == null ? code : null))
                        .GetAwaiter().GetResult();
                }
                catch (Exception ex) { report = "EXCEPTION: " + ex; }
                System.IO.File.WriteAllText(outPath, report);
                Shutdown();
                return;
            }
            if (string.Equals(e.Args[i], "--vaultwritetest", StringComparison.OrdinalIgnoreCase)
                || string.Equals(e.Args[i], "--backendtest", StringComparison.OrdinalIgnoreCase))
            {
                bool backend = string.Equals(e.Args[i], "--backendtest", StringComparison.OrdinalIgnoreCase);
                string inPath = e.Args[i + 1];
                string outPath = e.Args[i + 2];
                string report;
                try
                {
                    var lines = System.IO.File.ReadAllLines(inPath);
                    report = Task.Run(() => backend
                        ? VaultType.Vault.VaultLiveTest.RunBackendTestAsync(lines[0].Trim(), lines[1].Trim(), lines[2])
                        : VaultType.Vault.VaultLiveTest.RunWriteTestAsync(lines[0].Trim(), lines[1].Trim(), lines[2]))
                        .GetAwaiter().GetResult();
                }
                catch (Exception ex) { report = "EXCEPTION: " + ex; }
                System.IO.File.WriteAllText(outPath, report);
                Shutdown();
                return;
            }
        }

        // Dev-only: dump a single dialog card (tight, no shadow) for pixel comparison, then exit.
        for (int i = 0; i < e.Args.Length; i++)
        {
            if (string.Equals(e.Args[i], "--carddump", StringComparison.OrdinalIgnoreCase))
            {
                try { RunCardDump(e.Args[i + 1], e.Args[i + 2]); } catch (Exception ex) { System.IO.File.WriteAllText(e.Args[i + 2] + ".err", ex.ToString()); }
                Shutdown();
                return;
            }
            if (string.Equals(e.Args[i], "--show", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= e.Args.Length) { Shutdown(); return; }
                RunShow(e.Args[i + 1]);   // opens a live window; keeps running until it is closed
                return;
            }
        }

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

        // Dev-only live gallery: open every window at once (mock data) for hot-reload design work.
        if (e.Args.Any(a => string.Equals(a, "--gallery", StringComparison.OrdinalIgnoreCase)))
        {
            RunGalleryMode();
            return;
        }

        _mutex = new Mutex(true, "VaultType_SingleInstance_9F2A", out bool isNew);
        if (!isNew) { Shutdown(); return; }

        // Don't let a stray UI exception silently kill the whole tray app: log it and keep running.
        DispatcherUnhandledException += (_, ev) =>
        {
            LogCrash(ev.Exception);
            try { ShowBalloon(Loc.T("msg.error"), ev.Exception.Message); } catch { }
            ev.Handled = true;
        };
        // Background-thread (e.g. SSH-agent pipe) exceptions can't be handled, but log them before
        // the runtime tears the process down so a crash is never silent.
        AppDomain.CurrentDomain.UnhandledException += (_, ev) =>
        {
            if (ev.ExceptionObject is Exception ex) LogCrash(ex);
            else LogCrash(new Exception($"non-Exception throw: {ev.ExceptionObject}"));
        };
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, ev) =>
        {
            LogCrash(ev.Exception);
            ev.SetObserved();
        };

        _cfg = AppConfig.Load();
        Loc.Init(_cfg.Language);
        ProcessHardening.Apply(_cfg.AntiDebugger);

        foreach (var acc in _cfg.Accounts) _sessions.Add(new VaultSession(acc, _cfg));

        _hotkey = new HotkeyManager();
        _hotkey.Pressed += OnHotkey;
        bool hotkeyOk = _hotkey.Register(_cfg.Hotkey, out _);

        _idle = new IdleLockService(_cfg.IdleTimeoutMinutes);
        _idle.Lock += () => Dispatcher.Invoke(() => LockVault(true));

        if (_cfg.EnableTrayClick) _fgTracker = new ForegroundTracker();
        AutostartService.Set(_cfg.Autostart);   // keep the Run entry in sync with the preference

        SetupTray();
        ApplySshAgent();
        ApplyPasskeyProvider();
        if (hotkeyOk)
        {
            // greet only on the very first start after installation, not on every launch
            if (!_cfg.FirstRunNotified)
            {
                ShowBalloon(Loc.T("msg.runningTitle"), Loc.T("msg.runningMsg", _cfg.Hotkey));
                _cfg.FirstRunNotified = true;
                _cfg.Save();
            }
        }
        else
            MessageBox.Show(Loc.T("msg.hotkeyInUse", _cfg.Hotkey), "VaultType",
                            MessageBoxButton.OK, MessageBoxImage.Warning);

        // First launch after install: set up the first account right away instead of idling in the tray.
        if (_cfg.Accounts.Count == 0)
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

            if (_cfg.Accounts.Count == 0)
            {
                if (!await AddAccountAsync()) return;
            }
            else if (!AnyUnlocked && _sessions.Count == 1)
            {
                // Single account, nothing open yet: unlock it straight away (no chooser needed).
                if (!await UnlockSessionAsync(_sessions[0])) return;
            }
            // Otherwise fall through to the picker; any locked account shows up as a footer chip.

            // The URL read ran in parallel; only show a brief spinner if it isn't done yet.
            if (urlTask.IsCompleted) ctx.Url = await urlTask;
            else
            {
                var l = new LoadingWindow(_cfg.ExcludeFromScreenCapture);
                l.SetStatus(Loc.T("loading.reading"));
                l.Show();
                try { ctx.Url = await urlTask; } finally { l.Close(); }
            }

            var picker = new PickerWindow(_sessions, ctx, _cfg.DefaultUriMatch,
                _cfg.ExcludeFromScreenCapture, showAllFirst, UnlockSessionAsync);
            bool? ok = picker.ShowDialog();
            _idle.Arm(_cfg.IdleTimeoutMinutes);

            if (ok == true && picker.Result != null)
            {
                Dispatch(picker.Result, ctx);
                await MaybeOfferRemember(picker.Result, picker.Matches, ctx);
            }
        }
        catch (Exception ex) { ShowBalloon("Error", ex.Message); }
        finally { _busy = false; }
    }

    // Drive the initial setup on the first launch: get the CLI in place, then add the first account.
    private async Task RunFirstTimeSetup()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            await AddAccountAsync();
        }
        catch (Exception ex) { ShowBalloon("Error", ex.Message); }
        finally { _busy = false; }
    }

    // if they picked an entry we didn't auto-suggest, offer to remember it for next time
    private async Task MaybeOfferRemember(PickResult picked, IReadOnlyList<VaultItem> matches, ForegroundInfo ctx)
    {
        var s = picked.Session;
        var item = picked.Item;
        if (!s.Unlocked || matches.Contains(item)) return;
        string? uri = BuildRememberUri(ctx);
        if (uri == null) return;
        if (item.Uris.Any(u => string.Equals(u.Value, uri, StringComparison.OrdinalIgnoreCase))) return;

        string label = !string.IsNullOrEmpty(ctx.Url) ? Matcher.HostDomain(ctx.Url!).domain : ctx.Exe;
        var confirm = new ConfirmWindow(Loc.T("confirm.rememberTitle"),
            Loc.T("confirm.rememberMsg", uri, item.Name, label),
            _cfg.ExcludeFromScreenCapture);
        if (confirm.ShowDialog() != true) return;

        try
        {
            await s.Backend.AddUriAsync(item.Id, uri);
            var iu = new ItemUri { Value = uri };   // no explicit match -> follows the configured default
            Matcher.FillHostDomain(iu);
            item.Uris.Add(iu);
            ShowBalloon(Loc.T("msg.savedTitle"), Loc.T("msg.savedMsg", item.Name, label));
        }
        catch (Exception ex) { ShowBalloon(Loc.T("msg.error"), ex.Message); }
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
        var protector = r.Session.Protector;
        if (protector == null) return;

        // Actions that reveal the password/TOTP require re-prompt if the entry demands it.
        bool sensitive = r.Action is PickAction.TypeFull or PickAction.TypePassword or PickAction.TypeTotp
            or PickAction.CopyPassword or PickAction.CopyTotp;
        if (sensitive && r.Item.Reprompt && _cfg.HonorMasterPasswordReprompt && !VerifyMasterPassword(r.Session)) return;

        int secs = _cfg.ClipboardClearSeconds;
        switch (r.Action)
        {
            case PickAction.TypeFull:
                AutoTyper.Type(ctx.Hwnd, r.Item, protector, TypeAction.Full, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypeUsername:
                AutoTyper.Type(ctx.Hwnd, r.Item, protector, TypeAction.Username, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypePassword:
                AutoTyper.Type(ctx.Hwnd, r.Item, protector, TypeAction.Password, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.TypeTotp:
                AutoTyper.Type(ctx.Hwnd, r.Item, protector, TypeAction.Totp, _cfg.TypingDelayMs, _cfg.ClearFieldBeforeTyping); break;
            case PickAction.CopyUsername:
                ClipboardService.CopyUsername(r.Item, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedUser", secs)); break;
            case PickAction.CopyPassword:
                ClipboardService.CopyPassword(r.Item, protector, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedPass", secs)); break;
            case PickAction.CopyTotp:
                ClipboardService.CopyTotp(r.Item, protector, secs); ShowBalloon(Loc.T("msg.copiedTitle"), Loc.T("msg.copiedTotp", secs)); break;
        }
    }


    // Bring one existing account online (unlock, falling back to a fresh sign-in for that account).
    private Task<bool> UnlockSessionAsync(VaultSession s)
        => s.Cfg.SignedInBefore ? RunUnlockFlow(s) : RunSignInFlow(s, isNew: false);

    // Sign in a brand-new account and, on success, add it to the configuration.
    private async Task<bool> AddAccountAsync()
    {
        var acc = AccountConfig.CreateNew(_cfg.Accounts);
        var s = new VaultSession(acc, _cfg);
        try { Directory.CreateDirectory(acc.DataDir); } catch { }

        bool ok = await RunSignInFlow(s, isNew: true);
        if (!ok)
        {
            // discard the provisional, empty account directory
            s.Backend.Dispose();
            try { if (Directory.Exists(acc.DataDir)) Directory.Delete(acc.DataDir, true); } catch { }
        }
        return ok;
    }

    // The sign-in loop for one account (design "SignIn" dialog). On success the account's keys,
    // protector and decrypted items are loaded by the backend; a brand-new account is committed.
    private async Task<bool> RunSignInFlow(VaultSession s, bool isNew)
    {
        string server = s.Cfg.ServerUrl;
        string emailPrefill = s.Cfg.AccountEmail;
        string? pendingError = null;

        while (true)
        {
            var win = new SignInWindow(_cfg.ExcludeFromScreenCapture, emailPrefill, server);
            // An existing account carries its display + unlock preferences into the dialog, so
            // "edit" from the settings shows the current values instead of blank defaults.
            if (!isNew)
                win.PresetVault(s.Cfg.Name, s.Cfg.ColorHex, s.Cfg.UnlockMethod, s.Cfg.PinRequireMasterOnRestart);
            if (pendingError != null)
            {
                string errCopy = pendingError;
                win.Loaded += (_, __) => win.ShowError(errCopy);
                pendingError = null;
            }
            bool? ok = win.ShowDialog();
            if (ok != true) return false;

            // The dialog offers every design sign-in method; the backend supports e-mail and
            // API key today. The rest fail honestly instead of pretending.
            if (win.Method is "device" or "sso" or "passkey")
            {
                pendingError = Loc.T("signin.errMethodUnavailable");
                continue;
            }
            if (win.Password == null) return false;

            if (win.Email.Length > 0) emailPrefill = win.Email;
            server = win.Server;
            // Point the account (and thus the backend's HTTP client) at the chosen server before we call it.
            s.Cfg.ServerUrl = string.IsNullOrWhiteSpace(server) ? AccountConfig.UsCloud : server;

            // Snapshot the form values; the master password becomes wiped bytes the backend owns.
            byte[] pw = SecureStringUtil.ToUtf8Bytes(win.Password);
            bool useApiKey = win.Method == "apikey";
            string email = win.Email;
            string clientId = win.ClientId;
            // Keep the API client secret as wipeable bytes the backend owns (like the master
            // password), not a managed string that would linger unwipeable in the heap.
            byte[] clientSecret = useApiKey && win.ClientSecret != null
                ? SecureStringUtil.ToUtf8Bytes(win.ClientSecret) : Array.Empty<byte>();
            string? tfCode = string.IsNullOrWhiteSpace(win.TwoFactorCode) ? null : win.TwoFactorCode.Trim();
            int? tfProv = tfCode != null ? win.TwoFactorMethod : (int?)null;
            string prefUnlock = win.PreferredUnlock;
            byte[]? pinBytes = prefUnlock == "pin" && win.PinToSet != null ? SecureStringUtil.ToUtf8Bytes(win.PinToSet) : null;
            bool restartLock = win.RequireMasterOnRestart;
            string vaultName = win.VaultName;
            string colorHex = win.ColorHex;
            win.Password.Dispose();
            win.ClientSecret?.Dispose();
            win.PinToSet?.Dispose();

            var loading = new LoadingWindow(_cfg.ExcludeFromScreenCapture);
            loading.SetStatus(Loc.T("loading.signingin"));
            loading.Show();

            LoginResult? loginRes = null;
            string failMsg = "";
            try
            {
                // Run off the UI thread so the KDF (Argon2 can take ~1s) doesn't freeze the spinner.
                loginRes = await Task.Run(() => useApiKey
                    ? s.Backend.LoginApiKeyAsync(clientId, clientSecret, email, pw)
                    : s.Backend.LoginPasswordAsync(email, pw, tfCode, tfProv, null));
            }
            catch (Exception ex) { failMsg = ex.Message; }
            loading.Close();

            if (loginRes == null) { pendingError = failMsg.Length > 0 ? failMsg : Loc.T("unlock.errMaster"); continue; }
            if (loginRes.Status == LoginStatus.TwoFactorRequired) { pendingError = Loc.T("unlock.twofa"); continue; }
            if (loginRes.Status == LoginStatus.NewDeviceVerificationRequired) { pendingError = loginRes.Error; continue; }
            if (loginRes.Status != LoginStatus.Success) { pendingError = loginRes.Error.Length > 0 ? loginRes.Error : Loc.T("unlock.errMaster"); continue; }

            if (email.Length > 0) s.Cfg.AccountEmail = email;
            s.Cfg.ServerUrl = string.IsNullOrWhiteSpace(server) ? AccountConfig.UsCloud : server;
            s.Cfg.Kind = AccountConfig.KindFromServer(s.Cfg.ServerUrl);
            s.RebuildIcons(_cfg);   // now that the server is known, the icon service can use it
            s.Cfg.SignedInBefore = true;

            // preferred unlock method + display, straight from the dialog
            s.Cfg.UnlockMethod = prefUnlock;
            s.Cfg.PinRequireMasterOnRestart = restartLock;
            if (vaultName.Length > 0) s.Cfg.Name = vaultName;
            s.Cfg.ColorHex = colorHex;
            if (pinBytes != null)
            {
                try { PinUnlock.Enroll(s, pinBytes); }
                catch (Exception ex) { ShowBalloon(Loc.T("msg.error"), ex.Message); }
            }

            if (isNew)
            {
                if (s.Cfg.Name.Length == 0) s.Cfg.Name = s.Cfg.DeriveName();
                _cfg.Accounts.Add(s.Cfg);
                _sessions.Add(s);
            }
            _cfg.Save();   // persist the account (and its SignedInBefore/email/server)

            _idle.Arm(_cfg.IdleTimeoutMinutes);
            UpdateTray();
            return true;
        }
    }

    // The unlock loop for one signed-in account (design "Unlock" dialog). The visible input follows
    // the account's preferred unlock method; a stale session drops back to the sign-in form.
    private async Task<bool> RunUnlockFlow(VaultSession s)
    {
        string? pendingError = null;

        while (true)
        {
            string method = s.Cfg.UnlockMethod;
            if (method == "pin" && !PinUnlock.Available(s)) method = "password";
            if (method is "bio" or "passkey") method = "password";   // not implemented yet - honest fallback

            var win = new UnlockWindow(Loc.T("unlock.title"), "", _cfg.ExcludeFromScreenCapture, method);
            var choices = _sessions.Select(x => new AccountChoice
            {
                Id = x.Cfg.Id, Name = x.Cfg.Name, Email = x.Cfg.AccountEmail,
                Server = x.Cfg.ServerUrl, ColorHex = x.Cfg.ColorHex,
            }).ToList();
            win.SetAccounts(choices, _sessions.IndexOf(s));
            string? switchTo = null;
            win.AccountPicked += id => { switchTo = id; win.DialogResult = false; };
            if (pendingError != null)
            {
                string errCopy = pendingError;
                win.Loaded += (_, __) => win.ShowError(errCopy);
                pendingError = null;
            }

            bool? ok = win.ShowDialog();
            if (switchTo != null)
            {
                // the user switched vaults in the dropdown: continue the flow with that account
                var other = _sessions.FirstOrDefault(x => x.Cfg.Id == switchTo);
                if (other != null) { s = other; if (!other.Cfg.SignedInBefore) return await RunSignInFlow(other, isNew: false); }
                continue;
            }
            if (ok != true) return false;

            byte[] pw;
            bool viaPin = method == "pin";
            if (viaPin)
            {
                if (win.Pin == null) return false;
                pw = SecureStringUtil.ToUtf8Bytes(win.Pin);
                win.Pin.Dispose();
            }
            else
            {
                if (win.Password == null) return false;
                pw = SecureStringUtil.ToUtf8Bytes(win.Password);
                win.Password.Dispose();
            }

            var loading = new LoadingWindow(_cfg.ExcludeFromScreenCapture);
            loading.SetStatus(Loc.T("loading.unlocking"));
            loading.Show();

            UnlockStatus? unlockRes = null;
            string failMsg = "";
            try
            {
                unlockRes = await Task.Run(() => viaPin ? PinUnlock.Unlock(s, pw) : s.Backend.UnlockAsync(pw));
            }
            catch (Exception ex) { failMsg = ex.Message; }
            loading.Close();

            if (unlockRes == UnlockStatus.NeedsLogin) return await RunSignInFlow(s, isNew: false);
            if (unlockRes == UnlockStatus.WrongPassword)
            {
                pendingError = Loc.T(viaPin ? "unlock.errPinWrong" : "unlock.errMaster");
                continue;
            }
            if (unlockRes != UnlockStatus.Success)
            {
                pendingError = failMsg.Length > 0 ? failMsg : Loc.T("unlock.errMaster");
                continue;
            }

            _cfg.Save();
            _idle.Arm(_cfg.IdleTimeoutMinutes);
            UpdateTray();
            return true;
        }
    }

    // Synchronous unlock for the agent paths - SSH sign requests and passkey ceremonies - (already
    // on the UI thread inside Dispatcher.Invoke, so we can't await). The backend awaits with
    // ConfigureAwait(false), so blocking here is safe.
    private bool UnlockForAgent(VaultSession s, string subtitleKey = "ssh.unlockForKey")
    {
        string method = s.Cfg.UnlockMethod;
        if (method == "pin" && !PinUnlock.Available(s)) method = "password";
        if (method is "bio" or "passkey") method = "password";

        var win = new UnlockWindow(Loc.T("unlock.title"),
            Loc.T(subtitleKey), _cfg.ExcludeFromScreenCapture, method);
        var choices = _sessions.Select(x => new AccountChoice
        {
            Id = x.Cfg.Id, Name = x.Cfg.Name, Email = x.Cfg.AccountEmail, Server = x.Cfg.ServerUrl, ColorHex = x.Cfg.ColorHex,
        }).ToList();
        win.SetAccounts(choices, _sessions.IndexOf(s));
        if (win.ShowDialog() != true) return false;

        bool viaPin = method == "pin";
        var secure = viaPin ? win.Pin : win.Password;
        if (secure == null) return false;
        byte[] pw = SecureStringUtil.ToUtf8Bytes(secure);
        secure.Dispose();

        UnlockStatus st;
        try { st = Task.Run(() => viaPin ? PinUnlock.Unlock(s, pw) : s.Backend.UnlockAsync(pw)).GetAwaiter().GetResult(); }
        catch { st = UnlockStatus.Failed; }

        if (st == UnlockStatus.Success) { _cfg.Save(); _idle.Arm(_cfg.IdleTimeoutMinutes); UpdateTray(); return true; }
        return false;
    }

    private bool VerifyMasterPassword(VaultSession s)
    {
        var win = new UnlockWindow(Loc.T("unlock.confirmTitle"),
            Loc.T("unlock.confirmMsg"),
            _cfg.ExcludeFromScreenCapture, "password");
        if (win.ShowDialog() != true || win.Password == null) return false;
        byte[] pw = SecureStringUtil.ToUtf8Bytes(win.Password);
        win.Password.Dispose();
        return s.Backend.VerifyMasterPassword(pw);
    }

    // Lock every account: wipe all session keys and forget all items.
    private void LockVault(bool notify)
    {
        ClipboardService.ClearNow();
        foreach (var s in _sessions) s.Lock();
        _idle.Disarm();
        UpdateTray();
        if (notify) ShowBalloon(Loc.T("msg.lockedTitle"), Loc.T("msg.lockedMsg"));
    }

    // Sync every unlocked account and reload its entries.
    private async void SyncNow()
    {
        if (!AnyUnlocked) { ShowBalloon(Loc.T("msg.note"), Loc.T("msg.unlockFirst")); return; }
        if (_busy) return;
        _busy = true;
        _idle.Disarm();   // don't let the idle-lock dispose a session while the sync runs off-thread
        try
        {
            string? firstErr = null;
            foreach (var s in _sessions.Where(x => x.Unlocked).ToList())
            {
                try { await Task.Run(() => s.Backend.SyncAsync()); }
                catch (Exception ex) { firstErr ??= ex.Message; }
            }
            _cfg.Save();   // persist the accounts' fresh LastSyncUtc stamps
            UpdateTray();
            if (firstErr == null) ShowBalloon(Loc.T("msg.syncedTitle"), Loc.T("msg.syncedMsg", TotalItems));
            else ShowBalloon(Loc.T("msg.syncErr"), firstErr);
        }
        catch (Exception ex) { ShowBalloon(Loc.T("msg.syncErr"), ex.Message); }
        finally { _busy = false; if (AnyUnlocked) _idle.Arm(_cfg.IdleTimeoutMinutes); }
    }

    private bool _settingsOpen;

    private void OpenSettings()
    {
        // The settings are modal but a tray click spins its own message loop - don't stack a
        // second settings dialog on top of the first (easy to trigger now that a plain left
        // click opens the settings by default).
        if (_settingsOpen) return;
        _settingsOpen = true;
        try { OpenSettingsCore(); } finally { _settingsOpen = false; }
    }

    private void OpenSettingsCore()
    {
        _hotkey.Unregister();                 // don't let the global hotkey fire while it is being edited
        string prevLang = _cfg.Language;
        string prevHotkey = _cfg.Hotkey;
        bool langChanged = false;
        bool addAccount = false;
        bool hotkeyFailed;

        var rows = _sessions.Select(s => new AccountRow
        {
            Id = s.Cfg.Id,
            Name = s.Cfg.Name,
            ColorHex = s.Cfg.ColorHex,
            ServerLabel = ServerLabel(s.Cfg),
            Unlocked = s.Unlocked,
        }).ToList();

        try
        {
            var w = new SettingsWindow(_cfg, rows, _cfg.ExcludeFromScreenCapture)
            {
                SshStatusProvider = () => SshKeysWindow.StatusText(_sessions),
                CreateSshWindow = () => new SshKeysWindow(_sessions, _cfg, _cfg.ExcludeFromScreenCapture),
                EditAccount = EditAccountFromSettings,
            };
            if (w.ShowDialog() != true) return;
            _cfg.Save();
            ApplyAccountEdits(rows);
            addAccount = w.AddAccountRequested;

            if (_cfg.EnableTrayClick && _fgTracker == null) _fgTracker = new ForegroundTracker();
            else if (!_cfg.EnableTrayClick && _fgTracker != null) { _fgTracker.Dispose(); _fgTracker = null; }
            ApplySshAgent();
            if (AnyUnlocked) _idle.Arm(_cfg.IdleTimeoutMinutes);
            ApplyPasskeyProvider();
            UpdateTray();
            langChanged = !string.Equals(prevLang, _cfg.Language, StringComparison.OrdinalIgnoreCase);
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
        if (addAccount) AddAccountMenu();
    }

    // "Edit vault" from the settings list: re-run the sign-in dialog prefilled with the account's
    // data. On save the flow persists everything; mirror the result back into the settings row.
    private async Task EditAccountFromSettings(AccountRow row)
    {
        var s = _sessions.FirstOrDefault(x => x.Cfg.Id == row.Id);
        if (s == null || _busy) return;
        _busy = true;
        try
        {
            await RunSignInFlow(s, isNew: false);
            row.Name = s.Cfg.Name;
            row.ColorHex = s.Cfg.ColorHex;
            row.ServerLabel = ServerLabel(s.Cfg);
            row.Unlocked = s.Unlocked;
        }
        catch (Exception ex) { ShowBalloon(Loc.T("msg.error"), ex.Message); }
        finally { _busy = false; }
    }

    // Apply renames/recolours and process removals from the settings account list.
    private void ApplyAccountEdits(IReadOnlyList<AccountRow> rows)
    {
        var removed = new List<string>();
        foreach (var row in rows)
        {
            var s = _sessions.FirstOrDefault(x => x.Cfg.Id == row.Id);
            if (s == null) continue;
            if (row.Removed) { removed.Add(row.Id); continue; }
            string name = row.Name.Trim();
            if (name.Length > 0) s.Cfg.Name = name;
            s.Cfg.ColorHex = row.ColorHex;
        }
        foreach (var id in removed) RemoveAccount(id);
        _cfg.Save();
    }

    // Remove an account entirely: wipe its session, drop its persisted tokens and delete its data dir.
    private void RemoveAccount(string id)
    {
        var s = _sessions.FirstOrDefault(x => x.Cfg.Id == id);
        if (s == null) return;
        try { s.Backend.Logout(); } catch { }
        s.Backend.Dispose();
        _sessions.Remove(s);
        _cfg.Accounts.RemoveAll(a => a.Id == id);
        try { if (Directory.Exists(s.Cfg.DataDir)) Directory.Delete(s.Cfg.DataDir, true); } catch { }
    }

    private static string ServerLabel(AccountConfig a) => a.Kind switch
    {
        AccountKind.BitwardenUS => "Bitwarden.com (US)",
        AccountKind.BitwardenEU => "Bitwarden.eu (EU)",
        _ => a.ServerUrl,
    };

    // Guarded add-account entry point for the tray menu and the settings "Add account" button.
    private async void AddAccountMenu()
    {
        if (_busy) return;
        _busy = true;
        try { await AddAccountAsync(); }
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
    // async void: guard the whole body so a failure surfaces as a balloon, not an unhandled exception.
    private async void CheckForUpdates()
    {
        // Store edition: updates are delivered by the Microsoft Store, and a GitHub exe couldn't
        // replace an MSIX install anyway - send the user to the product page instead.
        if (AppInfo.IsPackaged)
        {
            try { Process.Start(new ProcessStartInfo(AppInfo.StoreUri) { UseShellExecute = true }); }
            catch (Exception ex) { LogCrash(ex); ShowBalloon(Loc.T("msg.error"), ex.Message); }
            return;
        }
        try
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
        catch (Exception ex)
        {
            LogCrash(ex);
            ShowBalloon(Loc.T("msg.error"), Loc.T("msg.updateFailed"));
        }
    }

    // ---- Live gallery (dev design work with hot reload) ----

    // Open every window at once with mock data, tiled across the desktop, so GUI edits can be
    // reviewed live under `dotnet watch`. Never touches the real vault or the single-instance mutex.
    private void RunGalleryMode()
    {
        Loc.Init("en");
        _cfg = new AppConfig { ShowIcons = false };

        // A stray click on a non-modal window's button would try to set DialogResult and throw;
        // swallow that so the gallery stays up while the user pokes around.
        DispatcherUnhandledException += (_, e) => { if (e.Exception is InvalidOperationException) e.Handled = true; };

        var ctx = new ForegroundInfo { Exe = "brave.exe", Title = "Sign in to GitHub", Url = "https://github.com/login" };

        var accPriv = new AccountConfig { Id = "p", Name = "Private", ColorHex = "#57C98A", ServerUrl = "https://vault.example.com", SignedInBefore = true };
        var accWork = new AccountConfig { Id = "w", Name = "Work", ColorHex = "#3B82F6", Kind = AccountKind.BitwardenEU, ServerUrl = AccountConfig.EuCloud, SignedInBefore = true };
        var sPriv = new VaultSession(accPriv, _cfg);
        sPriv.Backend.LoadMockUnlocked(BuildMockItems());
        var sWork = new VaultSession(accWork, _cfg);

        var wins = new List<Window>();

        var picker = new PickerWindow(new[] { sPriv, sWork }, ctx, 0, false, showAllFirst: true, _ => Task.FromResult(false));
        picker.Title = "VaultType - Picker";
        wins.Add(picker);

        var unlock = new UnlockWindow("Unlock vault", "", false);
        unlock.Pw.Password = "correct horse battery staple";
        unlock.SetAccounts(new List<AccountChoice>
        {
            new() { Id = "p", Email = "alex.doe@example.com", Server = "https://vault.example.com", ColorHex = "#57C98A" },
            new() { Id = "w", Email = "info@acme.io", Server = "https://vault.bitwarden.eu", ColorHex = "#3B82F6" },
        }, 0);
        unlock.Title = "VaultType - Unlock";
        wins.Add(unlock);

        var signin = new SignInWindow(false, "alex.doe@example.com");
        signin.Preset(method: "apikey", serverIndex: 0);
        signin.ClientIdBox.Text = "user.7f3a1c9e-2b4d-4e8a-9f10-abcdef123456";
        signin.ClientSecretBox.Password = "aXb9Kd2mNp7qRs4tUv1wYz0e";
        signin.Pw.Password = "correct horse battery staple";
        signin.Title = "VaultType - Sign in";
        wins.Add(signin);

        var settingsRows = new List<AccountRow>
        {
            new() { Id = "p", Name = "Private", ColorHex = "#57C98A", ServerLabel = "https://vault.example.com", Unlocked = true },
            new() { Id = "w", Name = "Work", ColorHex = "#3B82F6", ServerLabel = "Bitwarden.eu (EU)", Unlocked = false },
        };
        var settings = new SettingsWindow(_cfg, settingsRows, false);
        settings.Title = "VaultType - Settings";
        wins.Add(settings);

        var confirm = new ConfirmWindow("Remember this entry?",
            "Add 'https://github.com' to 'GitHub' so it is suggested for github.com next time?", false);
        confirm.Title = "VaultType - Confirm";
        wins.Add(confirm);

        var loading = new LoadingWindow(false);
        loading.SetStatus("Unlocking ...");
        loading.Title = "VaultType - Loading";
        wins.Add(loading);

        BuildGalleryControl(wins);
    }

    private static string GalleryMonitorFile =>
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vaulttype-gallery-monitor.txt");

    // Tiny always-on-top panel to move the whole gallery between monitors, re-tile, or quit. The
    // chosen monitor is remembered across watch restarts so edits don't kick the windows back.
    private void BuildGalleryControl(List<Window> wins)
    {
        var screens = WinForms.Screen.AllScreens;
        int primary = Array.FindIndex(screens, s => s.Primary); if (primary < 0) primary = 0;
        int idx = primary;
        try { if (int.TryParse(System.IO.File.ReadAllText(GalleryMonitorFile), out int v) && v >= 0 && v < screens.Length) idx = v; } catch { }

        var panel = new System.Windows.Controls.StackPanel { Margin = new Thickness(12) };
        System.Windows.Controls.Button Mk(string t)
        {
            var b = new System.Windows.Controls.Button
            {
                Content = t, Margin = new Thickness(0, 0, 0, 8),
                Style = (Style)Application.Current.FindResource("GhostButton"),
            };
            panel.Children.Add(b);
            return b;
        }
        var bNext = Mk("Alle Fenster -> naechster Monitor");
        var bTile = Mk("Neu anordnen");
        var bExit = Mk("Gallery beenden");

        var ctrl = new Window
        {
            Title = "VaultType Gallery", Width = 260, SizeToContent = SizeToContent.Height,
            WindowStyle = WindowStyle.ToolWindow, ResizeMode = ResizeMode.NoResize,
            Topmost = true, ShowInTaskbar = true, Content = panel,
            Background = (Brush)Application.Current.FindResource("WindowBg"),
        };
        ctrl.Show();
        ctrl.UpdateLayout();

        // Tile the whole gallery inside one monitor's work area (pixels -> DIPs via the DPI scale).
        void TileOnScreen(int screenIndex)
        {
            var sc = screens[screenIndex].WorkingArea;
            double dpi = System.Windows.Media.VisualTreeHelper.GetDpi(ctrl).DpiScaleX;
            if (dpi <= 0) dpi = 1;
            double left = sc.Left / dpi, top = sc.Top / dpi, right = sc.Right / dpi, bottom = sc.Bottom / dpi;
            double x = left + 12, y = top + 12, rowH = 0;
            foreach (var w in wins)
            {
                w.WindowStartupLocation = WindowStartupLocation.Manual;
                w.Topmost = false;
                w.ShowInTaskbar = true;
                if (!w.IsVisible) w.Show();
                w.UpdateLayout();
                w.Left = x;
                w.Top = y;
                x += w.ActualWidth + 12;
                rowH = Math.Max(rowH, w.ActualHeight);
                if (x + 320 > right) { x = left + 12; y += rowH + 12; rowH = 0; }
            }
            ctrl.Left = right - ctrl.ActualWidth - 12;
            ctrl.Top = bottom - ctrl.ActualHeight - 12;
        }

        bNext.Click += (_, __) =>
        {
            if (screens.Length < 2) return;
            idx = (idx + 1) % screens.Length;
            try { System.IO.File.WriteAllText(GalleryMonitorFile, idx.ToString()); } catch { }
            TileOnScreen(idx);
        };
        bTile.Click += (_, __) => TileOnScreen(idx);
        bExit.Click += (_, __) => Shutdown();

        TileOnScreen(idx);
    }

    // ---- Screenshot mode (README assets) ----

    // Render the app's windows to transparent PNGs with mock data, then quit.
    private void RunScreenshotMode(string outDir)
    {
        try
        {
            Loc.Init("en");
            try { System.IO.Directory.CreateDirectory(outDir); } catch { }

            _cfg = new AppConfig { ShowIcons = false };   // offline capture: letter avatars, no network requests

            var ctx = new ForegroundInfo { Exe = "brave.exe", Title = "Sign in to GitHub", Url = "https://github.com/login" };

            // Two accounts so the badge + locked-account chip show up.
            var accPriv = new AccountConfig { Id = "p", Name = "Private", ColorHex = "#57C98A", ServerUrl = "https://vault.example.com", SignedInBefore = true };
            var accWork = new AccountConfig { Id = "w", Name = "Work", ColorHex = "#3B82F6", Kind = AccountKind.BitwardenEU, ServerUrl = AccountConfig.EuCloud, SignedInBefore = true };
            var sPriv = new VaultSession(accPriv, _cfg);
            sPriv.Backend.LoadMockUnlocked(BuildMockItems());
            var sWork = new VaultSession(accWork, _cfg);   // left locked -> appears as a footer chip

            var picker = new PickerWindow(new[] { sPriv, sWork }, ctx, 0, false, showAllFirst: true,
                _ => Task.FromResult(false));
            CaptureWindow(picker, System.IO.Path.Combine(outDir, "picker.png"));

            var signinVw = new SignInWindow(false, "alex.doe@example.com", "https://vault.example.net");
            signinVw.Pw.Password = "correct horse battery staple";
            CaptureWindow(signinVw, System.IO.Path.Combine(outDir, "signin-vaultwarden.png"),
                beforeRender: () => MoveCaretToEnd(signinVw.Pw));

            var signinBw = new SignInWindow(false);
            signinBw.Preset(method: "apikey", serverIndex: 0);
            signinBw.ClientIdBox.Text = "user.7f3a1c9e-2b4d-4e8a-9f10-abcdef123456";
            signinBw.ClientSecretBox.Password = "aXb9Kd2mNp7qRs4tUv1wYz0e";
            signinBw.Pw.Password = "correct horse battery staple";
            CaptureWindow(signinBw, System.IO.Path.Combine(outDir, "signin-bitwarden.png"),
                beforeRender: () => MoveCaretToEnd(signinBw.Pw));

            var unlock = new UnlockWindow("Unlock vault", "", false);
            unlock.Pw.Password = "correct horse battery staple";
            CaptureWindow(unlock, System.IO.Path.Combine(outDir, "unlock.png"),
                beforeRender: () => MoveCaretToEnd(unlock.Pw));

            var unlockSwitch = new UnlockWindow("Unlock vault", "", false);
            unlockSwitch.Pw.Password = "correct horse battery staple";
            unlockSwitch.SetAccounts(new List<AccountChoice>
            {
                new() { Id = "p", Email = "alex.doe@example.com", Server = "https://vault.example.com", ColorHex = "#57C98A" },
                new() { Id = "w", Email = "info@acme.io", Server = "https://vault.bitwarden.eu", ColorHex = "#3B82F6" },
            }, 0);
            CaptureWindow(unlockSwitch, System.IO.Path.Combine(outDir, "unlock-switch.png"),
                beforeRender: () => { MoveCaretToEnd(unlockSwitch.Pw); unlockSwitch.OpenSwitcher(); });

            var settingsRows = new List<AccountRow>
            {
                new() { Id = "p", Name = "Private", ColorHex = "#57C98A", ServerLabel = "https://vault.example.com", Unlocked = true },
                new() { Id = "w", Name = "Work", ColorHex = "#3B82F6", ServerLabel = "Bitwarden.eu (EU)", Unlocked = false },
            };
            var settings = new SettingsWindow(_cfg, settingsRows, false);
            CaptureWindow(settings, System.IO.Path.Combine(outDir, "settings.png"));

            var settingsAT = new SettingsWindow(_cfg, settingsRows, false);
            settingsAT.NavAutoType.IsChecked = true;
            CaptureWindow(settingsAT, System.IO.Path.Combine(outDir, "settings-autotype.png"));
            var settingsSec = new SettingsWindow(_cfg, settingsRows, false);
            settingsSec.NavSecurity.IsChecked = true;
            CaptureWindow(settingsSec, System.IO.Path.Combine(outDir, "settings-security.png"));
            var settingsGen = new SettingsWindow(_cfg, settingsRows, false);
            settingsGen.NavGeneral.IsChecked = true;
            CaptureWindow(settingsGen, System.IO.Path.Combine(outDir, "settings-general.png"));

            // Integration tab with both features switched on, so the toggles read as "in use".
            var cfgInt = new AppConfig { ShowIcons = false, SshAgentEnabled = true, PasskeyProviderEnabled = true };
            var settingsInt = new SettingsWindow(cfgInt, settingsRows, false);
            settingsInt.ShowPasskeyAsSupported();
            settingsInt.SshKeyStatus.Text = Loc.T("ssh.many", 3);
            settingsInt.NavIntegration.IsChecked = true;
            CaptureWindow(settingsInt, System.IO.Path.Combine(outDir, "settings-integration.png"));

            var sshSession = new VaultSession(accPriv, _cfg);
            sshSession.Backend.LoadMockUnlocked(BuildMockItems());
            sshSession.Backend.LoadMockSshKeys(new List<SshKeyEntry>
            {
                new() { Name = "alex@laptop", Type = "ed25519", Fingerprint = "SHA256:a3Fq8LzvKmR2pXwT9hNcBs4Yd7Qe1oUj0Gf5RiZkL8", PublicKey = "ssh-ed25519 AAAA alex@laptop" },
                new() { Name = "github-deploy", Type = "ed25519", Fingerprint = "SHA256:pL2vNcHt7Wm3Qx9Ab6Ye0Rf4Zd8Kj1Uo5Gs2Vi7xQ0m", PublicKey = "ssh-ed25519 AAAA github-deploy" },
                new() { Name = "server-admin", Type = "rsa-4096", Fingerprint = "SHA256:7mRhTtqA2Wv9Kx3Nb6Yc0Rf8Zd4Ej1Uo5Gs7Vi2x4tBw", PublicKey = "ssh-rsa AAAA server-admin" },
            });
            var sshWin = new SshKeysWindow(new[] { sshSession, sWork }, _cfg, false);
            CaptureWindow(sshWin, System.IO.Path.Combine(outDir, "ssh-keys.png"));

            var tray = new TrayMenuWindow(new[] { sPriv, sWork }, "Ctrl + Alt + A", "2 min ago",
                new TrayMenuWindow.Actions());
            CaptureWindow(tray, System.IO.Path.Combine(outDir, "tray.png"));

            var confirm = new ConfirmWindow("Remember this entry?",
                "Add 'https://github.com' to 'GitHub' so it is suggested for github.com next time?", false);
            CaptureWindow(confirm, System.IO.Path.Combine(outDir, "confirm.png"));

            var loading = new LoadingWindow(false);
            loading.SetStatus("Unlocking ...");
            CaptureWindow(loading, System.IO.Path.Combine(outDir, "loading.png"));
        }
        catch (Exception ex) { MessageBox.Show(ex.ToString(), "Screenshot mode"); }
        finally { Shutdown(); }
    }

    // A non-null, empty session key so a mock VaultSession reads as "unlocked" for screenshots.
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

    // Render just the card element (by name) to a tight 1x PNG - no window margin, no drop shadow -
    // so it can be pixel-compared against the design card baseline (same border-box dimensions).
    private void CardDump(Window w, string cardName, string path, Action? beforeRender = null)
    {
        w.WindowStartupLocation = WindowStartupLocation.Manual;
        w.Left = -10000; w.Top = -10000; w.ShowInTaskbar = false; w.Topmost = false;
        w.Show();
        Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
        w.UpdateLayout();
        beforeRender?.Invoke();

        // Render in the resting (unfocused) state to match the static design - the window's smart
        // focus would otherwise green-highlight the first input.
        System.Windows.Input.FocusManager.SetFocusedElement(w, null);
        System.Windows.Input.Keyboard.ClearFocus();

        var card = w.FindName(cardName) as FrameworkElement ?? (FrameworkElement)w.Content;
        var savedEffect = card.Effect;
        var savedMargin = card is System.Windows.Controls.Border cb ? cb.Margin : new Thickness();
        card.Effect = null;
        if (card is System.Windows.Controls.Border b) b.Margin = new Thickness(0);

        Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
        w.UpdateLayout();

        int width = (int)System.Math.Ceiling(card.ActualWidth);
        int height = (int)System.Math.Ceiling(card.ActualHeight);
        var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(width, height, 96, 96,
            System.Windows.Media.PixelFormats.Pbgra32);
        rtb.Render(card);
        var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
        enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
        using (var fs = System.IO.File.Create(path)) enc.Save(fs);

        card.Effect = savedEffect;
        if (card is System.Windows.Controls.Border b2) b2.Margin = savedMargin;
        w.Close();
    }

    // Dev-only: dump one dialog's card to a tight PNG for pixel comparison against the design.
    private void RunCardDump(string name, string outPath)
    {
        Loc.Init("de");   // the design reference is German
        _cfg = new AppConfig { ShowIcons = false };
        var w = BuildMockDialog(name);
        if (w != null) CardDump(w, "Card", outPath);
    }

    // Dev-only: open a single dialog as a live on-screen window (to judge real text rendering).
    private void RunShow(string name)
    {
        Loc.Init("de");
        _cfg = new AppConfig { ShowIcons = false };
        var w = BuildMockDialog(name);
        if (w == null) { Shutdown(); return; }
        w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        w.Closed += (_, __) => Shutdown();
        w.Show();
        w.Activate();
    }

    // Build a dialog window populated with mock data (shared by --carddump and --show).
    private Window? BuildMockDialog(string name)
    {
        if (name == "unlock")
        {
            var unlock = new UnlockWindow("Vault entsperren",
                "Gib dein Master-Passwort ein, um den Vault zu entsperren.", false);
            unlock.SetAccounts(new List<AccountChoice>
            {
                new() { Id = "p", Name = "Privat", Email = "alex.doe@example.com", Server = "https://vault.example.com", ColorHex = "#8AA64A" },
                new() { Id = "w", Name = "Arbeit", Email = "info@acme.io", Server = "https://work.acme.io", ColorHex = "#3D7FC0" },
                new() { Id = "f", Name = "Familie", Email = "family@example.net", Server = "https://vault.bitwarden.com", ColorHex = "#A371F7" },
            }, 0);
            unlock.Pw.Password = "Sup3rSecretMasterKey!42";
            return unlock;
        }
        if (name == "signin")
        {
            // matches the design reference: self-hosted Vaultwarden? no - default: Bitwarden US,
            // e-mail method, master-password unlock, vault "Privat"
            var signin = new SignInWindow(false, "alex.doe@example.com");
            signin.Preset(method: "email", serverIndex: 0);
            signin.Pw.Password = "Sup3rSecretMasterKey!42";
            signin.VaultNameBox.Text = "Privat";
            return signin;
        }
        if (name == "picker")
        {
            var ctx = new ForegroundInfo { Exe = "brave.exe", Title = "Sign in to GitHub", Url = "https://github.com/login" };
            var accPriv = new AccountConfig { Id = "p", Name = "Privat", ColorHex = "#8AA64A", ServerUrl = "https://vault.example.com", SignedInBefore = true };
            var accWork = new AccountConfig { Id = "w", Name = "Team", ColorHex = "#3D7FC0", Kind = AccountKind.BitwardenEU, ServerUrl = AccountConfig.EuCloud, SignedInBefore = true };
            var sPriv = new VaultSession(accPriv, _cfg);
            sPriv.Backend.LoadMockUnlocked(BuildMockItems());
            var sWork = new VaultSession(accWork, _cfg);
            return new PickerWindow(new[] { sPriv, sWork }, ctx, 0, false, showAllFirst: true, _ => Task.FromResult(false));
        }
        if (name == "settings")
        {
            var rows = new List<AccountRow>
            {
                new() { Id = "p", Name = "Privat", ColorHex = "#8AA64A", ServerLabel = "Bitwarden (EU)", Unlocked = true },
                new() { Id = "w", Name = "Arbeit", ColorHex = "#3D7FC0", ServerLabel = "vault.acme.io", Unlocked = false },
                new() { Id = "f", Name = "Familie", ColorHex = "#A371F7", ServerLabel = "Bitwarden (US)", Unlocked = false },
            };
            var sw = new SettingsWindow(_cfg, rows, false)
            {
                SshStatusProvider = () => Loc.T("ssh.many", 4),
                CreateSshWindow = () => BuildMockDialog("ssh"),
            };
            sw.ShowPasskeyAsSupported();
            return sw;
        }
        if (name == "tray")
        {
            var aPriv = new AccountConfig { Id = "p", Name = "Privat", ColorHex = "#8AA64A", Kind = AccountKind.BitwardenEU, ServerUrl = AccountConfig.EuCloud, SignedInBefore = true };
            var aWork = new AccountConfig { Id = "w", Name = "Arbeit", ColorHex = "#3D7FC0", ServerUrl = "https://vault.acme.io", SignedInBefore = true };
            var aFam = new AccountConfig { Id = "f", Name = "Familie", ColorHex = "#A371F7", Kind = AccountKind.BitwardenUS, ServerUrl = AccountConfig.UsCloud, SignedInBefore = true };
            var sPriv = new VaultSession(aPriv, _cfg);
            sPriv.Backend.LoadMockUnlocked(BuildMockItems());   // unlocked -> shows an entry count
            var sWork = new VaultSession(aWork, _cfg);          // locked -> shows a lock icon
            var sFam = new VaultSession(aFam, _cfg);
            return new TrayMenuWindow(new[] { sPriv, sWork, sFam }, "Strg + Alt + A", "vor 2 Min.", new TrayMenuWindow.Actions());
        }
        if (name == "ssh")
        {
            var acc = new AccountConfig { Id = "p", Name = "Privat", ColorHex = "#8AA64A", ServerUrl = "https://vault.example.com", SignedInBefore = true };
            var s = new VaultSession(acc, _cfg);
            s.Backend.LoadMockUnlocked(BuildMockItems());
            s.Backend.LoadMockSshKeys(BuildMockSshKeys(s));
            return new SshKeysWindow(new[] { s }, _cfg, false);
        }
        return null;
    }

    // Mock SSH keys for the design gallery / card dump (display data only).
    private static List<SshKeyEntry> BuildMockSshKeys(VaultSession s)
    {
        SshKeyEntry K(string vault, string name, string type, string fp) => new()
        { Name = name, Type = type, Fingerprint = fp, PublicKey = "ssh-" + type + " AAAA " + name };
        // matches the design reference: vaults "Privat" + "Cloud" unlocked -> three keys shown
        return new List<SshKeyEntry>
        {
            K("Privat", "privat@laptop", "ed25519", "SHA256:a3Fq8LzvKmR2pXwT9hNcBs4Yd7Qe1oUj0Gf5RiZkL8"),
            K("Privat", "github-deploy", "ed25519", "SHA256:pL2vNcHt7Wm3Qx9Ab6Ye0Rf4Zd8Kj1Uo5Gs2Vi7xQ0m"),
            K("Cloud", "cloud-admin", "rsa-4096", "SHA256:7mRhTtqA2Wv9Kx3Nb6Yc0Rf8Zd4Ej1Uo5Gs7Vi2x4tBw"),
        };
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
    private TrayMenuWindow? _trayMenu;

    private void SetupTray()
    {
        // No WinForms menu: a left click triggers the configured action, a right click opens the
        // custom WPF menu (design "TrayMenu") at the cursor.
        _tray = new WinForms.NotifyIcon { Icon = BuildIcon(), Visible = true, Text = $"VaultType {AppInfo.Version}" };
        _tray.MouseUp += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Right) Dispatcher.Invoke(ShowTrayMenu);
            else if (e.Button == WinForms.MouseButtons.Left) OnTrayLeftClick();
        };
        _tray.BalloonTipClicked += (_, __) =>
        {
            if (_pendingUpdateUrl == null) return;
            try { Process.Start(new ProcessStartInfo(_pendingUpdateUrl) { UseShellExecute = true }); } catch { }
            _pendingUpdateUrl = null;
        };
        UpdateTray();
    }

    private void OnTrayLeftClick()
    {
        switch (_cfg.TrayClickAction)
        {
            case 1: OnTrayTrigger(); break;                          // start auto-type
            case 2: Dispatcher.Invoke(OpenSettings); break;          // open the settings
            default: Dispatcher.Invoke(ShowTrayMenu); break;         // open the menu
        }
    }

    private void ShowTrayMenu()
    {
        if (_trayMenu != null) { try { _trayMenu.Close(); } catch { } _trayMenu = null; }
        // Run each action on the next dispatcher turn (after the menu has fully closed) and guarded,
        // so a tray action can never take the whole app down.
        void Safe(Action a) => Dispatcher.BeginInvoke((Action)(() =>
        {
            try { a(); } catch (Exception ex) { LogCrash(ex); ShowBalloon(Loc.T("msg.error"), ex.Message); }
        }));
        var menu = new TrayMenuWindow(_sessions, _cfg.Hotkey, SyncHint(), new TrayMenuWindow.Actions
        {
            SelectAccount = s => { if (!s.Unlocked) _ = UnlockSessionAsync(s); },
            AutoType = OnHotkey,
            Sync = SyncNow,
            LockOne = LockOne,
            LockAll = () => LockVault(true),
            CheckUpdates = CheckForUpdates,
            OpenSettings = OpenSettings,
            Exit = ExitApp,
        }, _cfg.ExcludeFromScreenCapture);
        // Run the picked action only after the menu window is fully closed (avoids the
        // "Show/ShowDialog while a window is closing" crash), and guarded so it can't kill the app.
        menu.Closed += (_, __) =>
        {
            if (_trayMenu == menu) _trayMenu = null;
            if (menu.PendingAction is { } act) Safe(act);
        };
        _trayMenu = menu;
        var pos = WinForms.Cursor.Position;
        menu.ShowAt(pos.X, pos.Y);
    }

    private static void LogCrash(Exception ex)
    {
        try
        {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vaulttype-crash.log");
            System.IO.File.AppendAllText(path, $"[{DateTime.Now:s}] {ex}\n\n");
        }
        catch { }
    }

    // When were all signed-in vaults last in sync? The hint shows the OLDEST per-account stamp,
    // so "vor 5 Min." means: every vault synced at most 5 minutes ago. The stamps persist in the
    // config, so the hint survives restarts instead of resetting to "never".
    private string SyncHint()
    {
        var accounts = _cfg.Accounts.Where(a => a.SignedInBefore).ToList();
        if (accounts.Count == 0 || accounts.Any(a => a.LastSyncUtc == null)) return Loc.T("tray.syncNever");
        var span = DateTimeOffset.UtcNow - accounts.Min(a => a.LastSyncUtc!.Value);
        if (span.TotalMinutes < 1) return Loc.T("tray.syncJustNow");
        if (span.TotalHours < 1) return Loc.T("tray.syncAgo", (int)span.TotalMinutes);
        if (span.TotalDays < 1) return Loc.T("tray.syncAgoHours", (int)span.TotalHours);
        return Loc.T("tray.syncAgoDays", (int)span.TotalDays);
    }

    // Lock a single account.
    private void LockOne(VaultSession s)
    {
        if (!s.Unlocked) return;
        s.Lock();
        if (!AnyUnlocked) { ClipboardService.ClearNow(); _idle.Disarm(); }
        UpdateTray();
        ShowBalloon(Loc.T("msg.lockedTitle"), Loc.T("msg.lockedMsg"));
    }

    private void UpdateTray()
    {
        if (_tray != null) _tray.Text = AnyUnlocked ? $"VaultType — {Loc.T("tray.unlocked", TotalItems)}" : $"VaultType — {Loc.T("tray.locked")}";
        SyncPasskeyMetadata();
    }

    // Keep Windows' passkey picker in sync with the vault: every unlock/lock/sync path funnels
    // through UpdateTray, so the metadata cache follows the set of known passkeys. Locked accounts
    // contribute their persisted metadata (PasskeyMeta, like the SSH agent's ssh-public.json), so
    // their passkeys stay visible in the picker - choosing one pops the unlock window.
    private void SyncPasskeyMetadata()
    {
        if (!_cfg.PasskeyProviderEnabled) return;
        try
        {
            var creds = new List<Fido2Entry>();
            foreach (var s in _sessions)
            {
                if (s.Unlocked) creds.AddRange(s.Backend.Passkeys);
                else creds.AddRange(PasskeyMeta.Load(s.Cfg.PasskeyMetaPath).Select(m => m.ToEntry()));
            }
            PasskeyProvider.SyncCredentialMetadata(creds);
        }
        catch { }
    }

    private static Drawing.Icon BuildIcon()
    {
        // The app icon (window/taskbar/exe) keeps its designed margin, but that margin (~45% fill)
        // makes the notification-area icon look tiny next to others. So for the tray we crop the
        // glyph to its opaque bounds and redraw it nearly edge-to-edge at the DPI-scaled tray size.
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var s = asm.GetManifestResourceStream("VaultType.Assets.vaulttype.ico");
            if (s != null)
            {
                using var srcIcon = new Drawing.Icon(s, new Drawing.Size(256, 256));
                using var src = srcIcon.ToBitmap();
                Drawing.Rectangle glyph = OpaqueBounds(src);
                int size = Math.Max(16, WinForms.SystemInformation.SmallIconSize.Width);
                return CropFillIcon(src, glyph, size);
            }
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

    // Tight bounding box of the non-transparent pixels (alpha > 8).
    private static Drawing.Rectangle OpaqueBounds(Drawing.Bitmap bmp)
    {
        var data = bmp.LockBits(new Drawing.Rectangle(0, 0, bmp.Width, bmp.Height),
            System.Drawing.Imaging.ImageLockMode.ReadOnly, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        try
        {
            int minX = bmp.Width, minY = bmp.Height, maxX = -1, maxY = -1;
            unsafe
            {
                for (int y = 0; y < bmp.Height; y++)
                {
                    byte* row = (byte*)data.Scan0 + y * data.Stride;
                    for (int x = 0; x < bmp.Width; x++)
                    {
                        if (row[x * 4 + 3] > 8)   // BGRA, alpha byte
                        {
                            if (x < minX) minX = x;
                            if (x > maxX) maxX = x;
                            if (y < minY) minY = y;
                            if (y > maxY) maxY = y;
                        }
                    }
                }
            }
            return maxX < minX
                ? new Drawing.Rectangle(0, 0, bmp.Width, bmp.Height)
                : Drawing.Rectangle.FromLTRB(minX, minY, maxX + 1, maxY + 1);
        }
        finally { bmp.UnlockBits(data); }
    }

    // Draw the glyph region scaled to fill a square canvas of `size` edge-to-edge (aspect ratio
    // preserved), so it reads as large as the neighbouring tray icons.
    private static Drawing.Icon CropFillIcon(Drawing.Bitmap src, Drawing.Rectangle glyph, int size)
    {
        var bmp = new Drawing.Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (var g = Drawing.Graphics.FromImage(bmp))
        {
            g.Clear(Drawing.Color.Transparent);
            g.InterpolationMode = Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = Drawing.Drawing2D.PixelOffsetMode.HighQuality;

            float inner = size;                               // edge-to-edge, like neighbouring tray icons
            float scale = inner / Math.Max(glyph.Width, glyph.Height);
            float w = glyph.Width * scale, h = glyph.Height * scale;
            float x = (size - w) / 2f, y = (size - h) / 2f;
            g.DrawImage(src, new Drawing.RectangleF(x, y, w, h), glyph, Drawing.GraphicsUnit.Pixel);
        }
        IntPtr hicon = bmp.GetHicon();
        try { return (Drawing.Icon)Drawing.Icon.FromHandle(hicon).Clone(); }
        finally { DestroyIcon(hicon); bmp.Dispose(); }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

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

    // Start or stop the SSH agent to match the setting. The key list is read live per request,
    // so lock/unlock changes are picked up without restarting the pipe.
    private void ApplySshAgent()
    {
        if (_cfg.SshAgentEnabled)
        {
            // The built-in Windows ssh-agent service owns the same pipe; warn instead of failing silently.
            if (_sshAgent == null && SshAgentService.PipeAlreadyOwned())
                ShowBalloon(Loc.T("msg.sshPipeBusyTitle"), Loc.T("msg.sshPipeBusy"));
            _sshAgent ??= new SshAgentService(ListAgentKeys, AuthorizeSshSign);
            _sshAgent.Start();
        }
        else
        {
            _sshAgent?.Stop();
        }
    }

    // Every SSH key the agent should advertise: live keys from unlocked vaults, plus the persisted
    // public metadata of locked vaults (so a request can trigger an unlock). Disabled keys are hidden.
    private IReadOnlyList<AgentKey> ListAgentKeys()
    {
        var list = new List<AgentKey>();
        var seen = new HashSet<string>();
        foreach (var s in _sessions)
        {
            if (s.Unlocked)
            {
                foreach (var k in s.SshKeys)
                {
                    if (_cfg.SshDisabledKeys.Contains(k.Id) || !seen.Add(k.PublicKey)) continue;
                    list.Add(new AgentKey { PublicBlob = SshAgentService.PublicKeyToBlob(k.PublicKey), Comment = k.Name });
                }
            }
            else
            {
                foreach (var m in SshKeyMeta.Load(s.Cfg.SshMetaPath))
                {
                    if (_cfg.SshDisabledKeys.Contains(m.Id) || !seen.Add(m.PublicKey)) continue;
                    list.Add(new AgentKey { PublicBlob = SshAgentService.PublicKeyToBlob(m.PublicKey), Comment = m.Name });
                }
            }
        }
        return list.Where(k => k.PublicBlob.Length > 0).ToList();
    }

    // Resolve the private key for a sign request (called on the agent's pipe thread). If the owning
    // vault is locked, show the unlock window first; then honour the confirm-before-use setting.
    private AgentSignMaterial AuthorizeSshSign(byte[] publicBlob, string client)
    {
        return Dispatcher.Invoke(() =>
        {
            // Which account owns this key? Check unlocked sessions first, then persisted metadata.
            VaultSession? owner = _sessions.FirstOrDefault(s => s.Unlocked &&
                s.SshKeys.Any(k => SshAgentService.PublicKeyToBlob(k.PublicKey).AsSpan().SequenceEqual(publicBlob)));
            string? keyName = null;
            if (owner == null)
            {
                foreach (var s in _sessions.Where(s => !s.Unlocked))
                {
                    var meta = SshKeyMeta.Load(s.Cfg.SshMetaPath)
                        .FirstOrDefault(m => SshAgentService.PublicKeyToBlob(m.PublicKey).AsSpan().SequenceEqual(publicBlob));
                    if (meta != null) { owner = s; keyName = meta.Name; break; }
                }
                // The key belongs to a locked vault: unlock it now (the whole point of this flow).
                if (owner != null && !owner.Unlocked && !UnlockForAgent(owner)) return default;
            }
            if (owner == null) return default;

            var live = owner.SshKeys.FirstOrDefault(k =>
                SshAgentService.PublicKeyToBlob(k.PublicKey).AsSpan().SequenceEqual(publicBlob));
            if (live?.PrivateKey == null || owner.Protector == null) return default;
            keyName ??= live.Name;

            if (_cfg.SshConfirmEachUse)
            {
                var w = new ConfirmWindow(Loc.T("ssh.confirmTitle"),
                    Loc.T("ssh.confirmMsg", client, keyName), _cfg.ExcludeFromScreenCapture);
                if (w.ShowDialog() != true) return default;
            }
            return new AgentSignMaterial(live.PrivateKey, owner.Protector);
        });
    }

    // Register/unregister with Windows and host the pipe the plugin COM process forwards passkey
    // ceremonies through. The pipe runs whenever the feature is on - registration itself only
    // succeeds from the MSIX package, but the tray instance answering the pipe may be either build.
    private void ApplyPasskeyProvider()
    {
        PasskeyProvider.Apply(_cfg.PasskeyProviderEnabled);
        if (_cfg.PasskeyProviderEnabled)
        {
            _passkeyIpc ??= new PasskeyIpcServer(HandlePasskeyRequest);
            _passkeyIpc.Start();
        }
        else
        {
            _passkeyIpc?.Stop();
        }
    }

    // Runs on the pipe's worker thread; UI is marshalled to the Dispatcher like AuthorizeSshSign.
    private PasskeyIpcResponse HandlePasskeyRequest(PasskeyIpcRequest r) => r.Op switch
    {
        "status" => new PasskeyIpcResponse { Ok = true, Unlocked = AnyUnlocked },
        "getAssertion" => PasskeyGetAssertion(r),
        "makeCredential" => PasskeyMakeCredential(r),
        _ => PasskeyIpcResponse.Fail(CtapStatus.InvalidCommand),
    };

    private PasskeyIpcResponse PasskeyGetAssertion(PasskeyIpcRequest r)
    {
        if (string.IsNullOrEmpty(r.ClientDataHash)) return PasskeyIpcResponse.Fail(CtapStatus.MissingParameter);
        var allow = r.CredentialIds.Select(Convert.FromBase64String).ToList();
        byte[] clientDataHash = Convert.FromBase64String(r.ClientDataHash);

        return Dispatcher.Invoke(() =>
        {
            List<(VaultSession Session, Fido2Entry Cred)> Matches() =>
                _sessions.Where(s => s.Unlocked)
                    .SelectMany(s => s.Backend.Passkeys.Select(e => (s, e)))
                    .Where(t => string.Equals(t.e.RpId, r.RpId, StringComparison.OrdinalIgnoreCase)
                        && (allow.Count == 0
                            ? t.e.Discoverable
                            : allow.Any(id => id.AsSpan().SequenceEqual(t.e.CredentialId))))
                    .ToList();

            var matches = Matches();
            if (matches.Count == 0)
            {
                // A locked vault may hold the passkey: offer to unlock, then look again.
                foreach (var s in _sessions.Where(s => !s.Unlocked).ToList())
                {
                    if (!UnlockForAgent(s, "passkey.unlockForKey")) continue;
                    matches = Matches();
                    if (matches.Count > 0) break;
                }
            }
            // Do not log the plaintext RP id or the full list of every known RP - that is a
            // behavioural profile. Redacted tag only.
            PasskeyLog.Write($"assert: rp={PasskeyLog.Redact(r.RpId)} allow={allow.Count} matches={matches.Count}");
            if (matches.Count == 0) return PasskeyIpcResponse.Fail(CtapStatus.NoCredentials);

            var (owner, cred) = matches[0];

            // The plugin process performs Windows Hello when configured and the IPC peer is
            // authenticated as that very process (PasskeyIpcServer.IsTrustedClient), so UserVerified
            // can be trusted here. Without UV, still require an explicit click so a background
            // request can't exercise the key silently.
            if (!r.UserVerified)
            {
                string who = cred.UserName.Length > 0 ? cred.UserName : cred.ItemName;
                var w = new ConfirmWindow(Loc.T("passkey.confirmTitle"),
                    Loc.T("passkey.confirmUse", r.RpId, who), _cfg.ExcludeFromScreenCapture);
                if (w.ShowDialog() != true) return PasskeyIpcResponse.Fail(CtapStatus.OperationDenied);
            }

            if (cred.PrivateKey == null || owner.Protector == null)
                return PasskeyIpcResponse.Fail(CtapStatus.OtherError);

            byte flags = (byte)(Ctap2.FlagUserPresent | Ctap2.FlagBackupEligible | Ctap2.FlagBackedUp
                | (r.UserVerified ? Ctap2.FlagUserVerified : 0));
            // Signature counter follows the vault value, which Bitwarden keeps at 0 - a 0 signCount
            // tells the RP the authenticator doesn't provide a counter, so it skips clone detection.
            // We intentionally don't increment/persist it (there is no per-assertion writeback).
            byte[] authData = Ctap2.BuildAuthenticatorData(r.RpId, flags, cred.Counter);
            byte[]? sig = Fido2Signer.SignAssertion(cred.PrivateKey, owner.Protector, authData, clientDataHash);
            if (sig == null) return PasskeyIpcResponse.Fail(CtapStatus.OtherError);

            return new PasskeyIpcResponse
            {
                Ok = true,
                CredentialId = Convert.ToBase64String(cred.CredentialId),
                AuthData = Convert.ToBase64String(authData),
                Signature = Convert.ToBase64String(sig),
                UserHandle = cred.UserHandle.Length > 0 ? Convert.ToBase64String(cred.UserHandle) : null,
                UserName = cred.UserName,
                UserDisplayName = cred.UserDisplayName,
                // Always 1: we return exactly one assertion and do not implement getNextAssertion,
                // so reporting >1 would tell the client to fetch credentials it can never retrieve.
                Count = 1,
            };
        });
    }

    private PasskeyIpcResponse PasskeyMakeCredential(PasskeyIpcRequest r)
    {
        var exclude = r.CredentialIds.Select(Convert.FromBase64String).ToList();

        // Confirmation and unlock happen on the UI thread; the network write below must not.
        VaultSession? owner = null;
        var denied = Dispatcher.Invoke(() =>
        {
            owner = _sessions.FirstOrDefault(s => s.Unlocked);
            if (owner == null)
                foreach (var s in _sessions)
                    if (UnlockForAgent(s, "passkey.unlockForKey")) { owner = s; break; }
            if (owner == null) return PasskeyIpcResponse.Fail(CtapStatus.OperationDenied);

            if (exclude.Count > 0 && _sessions.Where(s => s.Unlocked)
                    .SelectMany(s => s.Backend.Passkeys)
                    .Any(e => exclude.Any(id => id.AsSpan().SequenceEqual(e.CredentialId))))
                return PasskeyIpcResponse.Fail(CtapStatus.CredentialExcluded);

            var w = new ConfirmWindow(Loc.T("passkey.confirmTitle"),
                Loc.T("passkey.confirmCreate", r.RpId, owner.Cfg.Name), _cfg.ExcludeFromScreenCapture);
            if (w.ShowDialog() != true) return PasskeyIpcResponse.Fail(CtapStatus.OperationDenied);
            return null;
        });
        if (denied != null) return denied;

        PasskeyLog.Write($"create: rp={r.RpId} account={owner!.Cfg.Name}");
        var created = Task.Run(() => owner!.Backend.CreatePasskeyAsync(
            r.RpId, r.RpName,
            r.UserId != null ? Convert.FromBase64String(r.UserId) : Array.Empty<byte>(),
            r.UserName, r.UserDisplayName, r.Discoverable)).GetAwaiter().GetResult();
        PasskeyLog.Write($"create: {(created == null ? "FAILED" : "ok")}");
        if (created == null) return PasskeyIpcResponse.Fail(CtapStatus.OtherError);

        // The vault re-sync runs in the background, so the fresh passkey is not in Backend.Passkeys
        // yet - announce it to the Windows picker right away from the request data.
        try
        {
            var announced = _sessions.Where(s => s.Unlocked).SelectMany(s => s.Backend.Passkeys).ToList();
            announced.Add(new Fido2Entry
            {
                CredentialId = created.Value.CredentialId,
                RpId = r.RpId,
                RpName = r.RpName ?? "",
                UserHandle = r.UserId != null ? Convert.FromBase64String(r.UserId) : Array.Empty<byte>(),
                UserName = r.UserName ?? "",
                UserDisplayName = r.UserDisplayName ?? "",
                ItemName = r.RpId,
                Discoverable = r.Discoverable,
            });
            PasskeyProvider.SyncCredentialMetadata(announced);
        }
        catch { }

        byte flags = (byte)(Ctap2.FlagUserPresent | Ctap2.FlagBackupEligible | Ctap2.FlagBackedUp
            | Ctap2.FlagAttestedCredentialData | (r.UserVerified ? Ctap2.FlagUserVerified : 0));
        byte[] cose = Ctap2.EncodeCoseEs256PublicKey(created.Value.PublicKey);
        byte[] authData = Ctap2.BuildAuthenticatorData(r.RpId, flags, 0, created.Value.CredentialId, cose);
        return new PasskeyIpcResponse { Ok = true, AuthData = Convert.ToBase64String(authData) };
    }

    private void ExitApp()
    {
        LockVault(false);
        _sshAgent?.Dispose();
        _passkeyIpc?.Dispose();
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
