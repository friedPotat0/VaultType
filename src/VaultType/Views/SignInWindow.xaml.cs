using System.Linq;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Config;
using VaultType.Security;
using Button = System.Windows.Controls.Button;
using RadioButton = System.Windows.Controls.RadioButton;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace VaultType.Views;

// The sign-in dialog (design "SignIn"): server picker, sign-in method pills, mode-specific
// fields, preferred-unlock pills, and the vault display (avatar colour + name).
public partial class SignInWindow : Window
{
    // ---- results (read after ShowDialog() == true) ----
    public string Server { get; private set; } = "";           // resolved URL
    public string Method { get; private set; } = "email";      // email | apikey | device | sso | passkey
    public string Email { get; private set; } = "";
    public SecureString? Password { get; private set; }
    public string ClientId { get; private set; } = "";
    public SecureString? ClientSecret { get; private set; }
    public string TwoFactorCode { get; private set; } = "";
    public int TwoFactorMethod { get; private set; }           // Bitwarden provider id
    public string SsoOrg { get; private set; } = "";
    public string PreferredUnlock { get; private set; } = "password";   // password | pin | bio | passkey
    public SecureString? PinToSet { get; private set; }
    public bool RequireMasterOnRestart { get; private set; } = true;
    public string VaultName => VaultNameBox.Text.Trim();
    public string ColorHex => AccountConfig.Palette[_palIndex % AccountConfig.Palette.Length];

    private static readonly string[] ServerLabels =
    {
        "Bitwarden.com (US)", "Bitwarden.eu (EU)", "Bitwarden (self-hosted)", "Vaultwarden (self-hosted)",
    };
    // (label key, method id); passkey is hidden for Vaultwarden (no PRF login support there)
    private static readonly (string Key, string Id)[] Methods =
    {
        ("signin.methodEmail", "email"), ("signin.methodApiKey", "apikey"), ("signin.methodDevice", "device"),
        ("signin.methodSso", "sso"), ("signin.methodPasskey", "passkey"),
    };
    private static readonly (string Key, string Id)[] UnlockMethods =
    {
        ("signin.unlockPassword", "password"), ("signin.unlockPin", "pin"),
        ("signin.unlockBio", "bio"), ("signin.unlockPasskey", "passkey"),
    };
    // 2FA provider ids: 0 Authenticator, 1 E-Mail, 3 YubiKey, 7 Passkey (WebAuthn), 2 Duo
    private static readonly (string Label, int Provider)[] TwofaOptions =
    {
        ("Authenticator", 0), ("E-Mail", 1), ("YubiKey", 3), ("Passkey", 7), ("Duo", 2),
    };

    private readonly bool _excludeCapture;
    private int _serverIndex;
    private string _method = "email";
    private string _prefUnlock = "password";
    private int _twofaIndex;
    private int _palIndex;
    private bool _restartLock = true;
    private string? _dropdown;   // "server" | "twofa" | null

    private bool IsSelfHosted => _serverIndex >= 2;
    private bool IsVaultwarden => _serverIndex == 3;

    public SignInWindow(bool excludeCapture, string emailPrefill = "", string serverPrefill = "")
    {
        InitializeComponent();
        // Never taller than the desktop: the API-key layout alone is ~950 DIP, which is more than a
        // 13" laptop at 200% scaling has left after the taskbar. Beyond this the card scrolls.
        MaxHeight = SystemParameters.WorkArea.Height;
        _excludeCapture = excludeCapture;

        _serverIndex = string.Equals(serverPrefill, AccountConfig.UsCloud, StringComparison.OrdinalIgnoreCase) ? 0
            : string.Equals(serverPrefill, AccountConfig.EuCloud, StringComparison.OrdinalIgnoreCase) ? 1
            : string.IsNullOrWhiteSpace(serverPrefill) ? 0 : 3;
        if (IsSelfHosted) UrlBox.Text = serverPrefill;
        EmailBox.Text = emailPrefill;
        DevEmailBox.Text = emailPrefill;

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;
        Refresh();
    }

    // Preselect state (mock dialogs / retry loop).
    public void Preset(string? method = null, int? serverIndex = null, string? prefUnlock = null)
    {
        if (serverIndex is int s) _serverIndex = Math.Clamp(s, 0, ServerLabels.Length - 1);
        if (method != null) _method = method;
        if (prefUnlock != null) _prefUnlock = prefUnlock;
        Refresh();
    }

    // Prefill the vault display + unlock preference (editing an existing account).
    public void PresetVault(string name, string colorHex, string prefUnlock, bool restartLock)
    {
        VaultNameBox.Text = name;
        _palIndex = Math.Max(0, Array.IndexOf(AccountConfig.Palette, colorHex));
        _prefUnlock = prefUnlock;
        _restartLock = restartLock;
        Refresh();
    }

    public void SetDevicePhrase(string phrase) => DevicePhrase.Text = phrase;

    public void ShowError(string message)
    {
        Error.Text = message;
        Error.Visibility = Visibility.Visible;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        Activate();
        if (IsSelfHosted && UrlBox.Text.Length == 0) UrlBox.Focus();
        else if (_method == "email" && EmailBox.Text.Length == 0) EmailBox.Focus();
        else if (_method == "email") Pw.Focus();
    }

    // ---- layout refresh (visibility per server / method / pref) ----

    private void Refresh()
    {
        ServerLabel.Text = ServerLabels[_serverIndex];
        UrlGroup.Visibility = IsSelfHosted ? Visibility.Visible : Visibility.Collapsed;

        // Vaultwarden hides the passkey options
        if (IsVaultwarden && _method == "passkey") _method = "email";
        if (IsVaultwarden && _prefUnlock == "passkey") _prefUnlock = "password";
        BuildPills(MethodPills, Methods.Where(m => !(m.Id == "passkey" && IsVaultwarden)).ToArray(), _method,
                   id => { _method = id; _dropdown = null; Refresh(); });
        BuildPills(UnlockPills, UnlockMethods.Where(m => !(m.Id == "passkey" && IsVaultwarden)).ToArray(), _prefUnlock,
                   id => { _prefUnlock = id; Refresh(); });

        // The e-mail is the KDF salt for the master key, so the API-key grant needs it as well -
        // only the 2FA fields below it belong to the password grant alone.
        EmailGroup.Visibility = _method is "email" or "apikey" ? Visibility.Visible : Visibility.Collapsed;
        TwofaGroup.Visibility = _method == "email" ? Visibility.Visible : Visibility.Collapsed;
        ApiGroup.Visibility = _method == "apikey" ? Visibility.Visible : Visibility.Collapsed;
        SsoGroup.Visibility = _method == "sso" ? Visibility.Visible : Visibility.Collapsed;
        SsoWarn.Visibility = IsVaultwarden ? Visibility.Visible : Visibility.Collapsed;
        DeviceGroup.Visibility = _method == "device" ? Visibility.Visible : Visibility.Collapsed;
        PasskeyHint.Visibility = _method == "passkey" ? Visibility.Visible : Visibility.Collapsed;
        MasterGroup.Visibility = _method is "email" or "apikey" or "sso" ? Visibility.Visible : Visibility.Collapsed;
        PinGroup.Visibility = _prefUnlock == "pin" ? Visibility.Visible : Visibility.Collapsed;

        TwofaLabel.Text = TwofaOptions[_twofaIndex].Label;
        OkLabel.Text = Loc.T(_method switch
        {
            "device" => "signin.btnDevice",
            "passkey" => "signin.btnPasskey",
            _ => "signin.btn",
        });

        RestartLockBox.Background = _restartLock ? (Brush)FindResource("Accent") : Brushes.Transparent;
        RestartLockBox.BorderBrush = _restartLock ? (Brush)FindResource("Accent") : (Brush)FindResource("BorderStrong");
        RestartLockCheck.Visibility = _restartLock ? Visibility.Visible : Visibility.Collapsed;

        UpdateAvatar();
        UpdatePlaceholders();
    }

    // Design pills: flex 1 1 auto - content width plus an equal share of the leftover space.
    private void BuildPills(FlexRowPanel host, (string Key, string Id)[] items, string selected, Action<string> pick)
    {
        host.Children.Clear();
        foreach (var (key, id) in items)
        {
            string idCopy = id;
            var pill = new RadioButton
            {
                Style = (Style)FindResource("SegPill"),
                Content = Loc.T(key),
                IsChecked = id == selected,
                GroupName = host.Name,
            };
            pill.Checked += (_, __) => pick(idCopy);
            host.Children.Add(pill);
        }
    }

    private void UpdateAvatar()
    {
        string name = VaultNameBox.Text.Trim();
        AvatarInitial.Text = name.Length > 0 ? name[..1].ToUpperInvariant() : "?";
        var c = (Color)ColorConverter.ConvertFromString(AccountConfig.Palette[_palIndex % AccountConfig.Palette.Length]);
        var dark = Color.FromRgb((byte)(c.R * 0.62), (byte)(c.G * 0.62), (byte)(c.B * 0.62));
        AvatarBtn.Background = new System.Windows.Media.LinearGradientBrush(c, dark, new Point(0.12, 0), new Point(0.88, 1));
    }

    private void UpdatePlaceholders()
    {
        UrlPlaceholder.Visibility = UrlBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        EmailPlaceholder.Visibility = EmailBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        DevEmailPlaceholder.Visibility = DevEmailBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClientIdPlaceholder.Visibility = ClientIdBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClientSecretPlaceholder.Visibility = ClientSecretBox.SecurePassword.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        SsoPlaceholder.Visibility = SsoBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        TwofaCodePlaceholder.Visibility = TwofaCodeBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        PwPlaceholder.Visibility = Pw.SecurePassword.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        PinPlaceholder.Visibility = PinBox.SecurePassword.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        VaultNamePlaceholder.Visibility = VaultNameBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AnyText_Changed(object sender, TextChangedEventArgs e) => UpdatePlaceholders();
    private void AnyPw_Changed(object sender, RoutedEventArgs e) => UpdatePlaceholders();
    private void VaultName_Changed(object sender, TextChangedEventArgs e) { UpdateAvatar(); UpdatePlaceholders(); }
    private void Avatar_Click(object sender, RoutedEventArgs e) { _palIndex = (_palIndex + 1) % AccountConfig.Palette.Length; UpdateAvatar(); }
    private void RestartLock_Click(object sender, MouseButtonEventArgs e) { _restartLock = !_restartLock; Refresh(); }

    // ---- dropdowns (overlay panels, like the design) ----

    private void ServerTrigger_Click(object sender, RoutedEventArgs e) => ToggleDropdown("server", ServerTrigger);
    private void TwofaTrigger_Click(object sender, RoutedEventArgs e) => ToggleDropdown("twofa", TwofaTrigger);
    private void Backdrop_Click(object sender, MouseButtonEventArgs e) => CloseDropdown();

    private void ToggleDropdown(string which, ToggleButton trigger)
    {
        trigger.IsChecked = false;   // the toggle look stays managed by the overlay
        if (_dropdown == which) { CloseDropdown(); return; }
        _dropdown = which;
        DropdownItems.Children.Clear();

        if (which == "server")
        {
            for (int i = 0; i < ServerLabels.Length; i++)
            {
                if (i == _serverIndex) continue;   // the design lists only the other options
                int idx = i;
                AddDropdownRow(ServerLabels[i], () => { _serverIndex = idx; CloseDropdown(); Refresh(); });
            }
        }
        else
        {
            for (int i = 0; i < TwofaOptions.Length; i++)
            {
                if (i == _twofaIndex) continue;
                int idx = i;
                AddDropdownRow(TwofaOptions[i].Label, () => { _twofaIndex = idx; CloseDropdown(); Refresh(); });
            }
        }

        Overlay.Visibility = Visibility.Visible;
        Overlay.UpdateLayout();
        var p = trigger.TranslatePoint(new Point(0, trigger.ActualHeight + 6), Overlay);
        Canvas.SetLeft(DropdownMenu, p.X);
        Canvas.SetTop(DropdownMenu, p.Y);
        DropdownMenu.Width = trigger.ActualWidth;
        // never taller than the window: cap the menu and let its ScrollViewer take over
        DropdownMenu.MaxHeight = Math.Max(80, Overlay.ActualHeight - p.Y - 8);
    }

    private void AddDropdownRow(string label, Action pick)
    {
        var row = new Button
        {
            Style = (Style)FindResource("DropdownRow"),
            Content = new TextBlock { Text = label, Foreground = (Brush)FindResource("TextBody"), FontSize = 13 },
        };
        row.Click += (_, __) => pick();
        DropdownItems.Children.Add(row);
    }

    private void CloseDropdown()
    {
        _dropdown = null;
        Overlay.Visibility = Visibility.Collapsed;
    }

    // ---- submit ----

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Error.Visibility = Visibility.Collapsed;
        string url = _serverIndex switch
        {
            0 => AccountConfig.UsCloud,
            1 => AccountConfig.EuCloud,
            _ => UrlBox.Text.Trim(),
        };
        if (IsSelfHosted && url.Length == 0) { ShowError(Loc.T("unlock.errServer")); UrlBox.Focus(); return; }

        switch (_method)
        {
            case "email":
                if (EmailBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errEmail")); EmailBox.Focus(); return; }
                if (Pw.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errMaster")); Pw.Focus(); return; }
                break;
            case "apikey":
                if (ClientIdBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errClientId")); ClientIdBox.Focus(); return; }
                if (ClientSecretBox.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errClientSecret")); ClientSecretBox.Focus(); return; }
                if (EmailBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errEmail")); EmailBox.Focus(); return; }
                if (Pw.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errMaster")); Pw.Focus(); return; }
                break;
            case "device":
                if (DevEmailBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errEmail")); DevEmailBox.Focus(); return; }
                break;
            case "sso":
                if (SsoBox.Text.Trim().Length == 0) { ShowError(Loc.T("signin.errSsoOrg")); SsoBox.Focus(); return; }
                if (Pw.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errMaster")); Pw.Focus(); return; }
                break;
        }
        if (_prefUnlock == "pin" && PinBox.SecurePassword.Length == 0)
        {
            ShowError(Loc.T("signin.errPin")); PinBox.Focus(); return;
        }

        Server = url;
        Method = _method;
        Email = (_method == "device" ? DevEmailBox.Text : EmailBox.Text).Trim();
        Password = Pw.SecurePassword;
        ClientId = ClientIdBox.Text.Trim();
        // Only capture the secret / PIN when the chosen method actually uses it; otherwise leave it
        // null so no unused SecureString lingers undisposed.
        ClientSecret = _method == "apikey" ? ClientSecretBox.SecurePassword : null;
        TwoFactorCode = TwofaCodeBox.Text.Trim();
        TwoFactorMethod = TwofaOptions[_twofaIndex].Provider;
        SsoOrg = SsoBox.Text.Trim();
        PreferredUnlock = _prefUnlock;
        PinToSet = _prefUnlock == "pin" ? PinBox.SecurePassword : null;
        RequireMasterOnRestart = _restartLock;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Pw_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
        else if (e.Key == Key.Escape) Cancel_Click(sender, e);
    }
}
