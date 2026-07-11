using System.Security;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Views;

public partial class UnlockWindow : Window
{
    public SecureString? Password { get; private set; }   // master password
    public string Email { get; private set; } = "";
    public string Server { get; private set; } = "";
    public bool UseApiKey { get; private set; }
    public string ClientId { get; private set; } = "";
    public SecureString? ClientSecret { get; private set; }
    public string TwoFactorCode { get; private set; } = "";
    public int TwoFactorMethod { get; private set; } // 0 = authenticator, 1 = email, 3 = YubiKey

    private readonly bool _loginMode;
    private readonly bool _excludeCapture;

    public UnlockWindow(string heading, string subtitle, bool loginMode, string email, string server, bool excludeCapture)
    {
        InitializeComponent();
        _loginMode = loginMode;
        _excludeCapture = excludeCapture;

        Heading.Text = heading;
        Subtitle.Text = subtitle;
        if (string.IsNullOrEmpty(subtitle))
        {
            Subtitle.Visibility = Visibility.Collapsed;
            Heading.Margin = new Thickness(0, 18, 0, 16);   // no subtitle -> give the heading room below
        }
        OkBtn.Content = loginMode ? Loc.T("unlock.btnSignin") : Loc.T("unlock.btnUnlock");
        EmailBox.Text = email;
        ServerBox.Text = server;

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;
        UpdateFields();
    }

    private void ApiKey_Changed(object sender, RoutedEventArgs e) => UpdateFields();
    private void Account_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        if (AccountBox.SelectedIndex == 1) ApiKeyChk.IsChecked = true;   // API key is the reliable path for bitwarden.com
        UpdateFields();
    }

    private void UpdateFields()
    {
        bool vw = AccountBox.SelectedIndex == 0;                       // 0 = Vaultwarden, 1 = Bitwarden.com
        bool api = _loginMode && !vw && ApiKeyChk.IsChecked == true;   // API key only makes sense for bitwarden.com
        AccountTypeGroup.Visibility = _loginMode ? Visibility.Visible : Visibility.Collapsed;
        ServerGroup.Visibility = _loginMode && vw ? Visibility.Visible : Visibility.Collapsed;
        ApiKeyChk.Visibility = _loginMode && !vw ? Visibility.Visible : Visibility.Collapsed;
        ApiHint.Visibility = api ? Visibility.Visible : Visibility.Collapsed;
        EmailGroup.Visibility = _loginMode && !api ? Visibility.Visible : Visibility.Collapsed;
        ClientIdGroup.Visibility = api ? Visibility.Visible : Visibility.Collapsed;
        ClientSecretGroup.Visibility = api ? Visibility.Visible : Visibility.Collapsed;
        TwoFactorGroup.Visibility = _loginMode && !api ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        Activate();
        if (_loginMode)
        {
            bool vw = AccountBox.SelectedIndex == 0;
            if (vw && ServerBox.Text.Length == 0) ServerBox.Focus();
            else if (!vw && ApiKeyChk.IsChecked == true) ClientIdBox.Focus();
            else if (EmailBox.Text.Length == 0) EmailBox.Focus();
            else Pw.Focus();
        }
        else Pw.Focus();
    }

    public void ShowError(string message)
    {
        Error.Text = message;
        Error.Visibility = Visibility.Visible;
        Pw.Clear();
        Pw.Focus();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        bool vw = AccountBox.SelectedIndex == 0;
        bool api = _loginMode && !vw && ApiKeyChk.IsChecked == true;

        if (Pw.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errMaster")); return; }
        if (_loginMode && vw && ServerBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errServer")); return; }
        if (api)
        {
            if (ClientIdBox.Text.Trim().Length == 0) { ShowError(Loc.T("unlock.errClientId")); return; }
            if (ClientSecretBox.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errClientSecret")); return; }
        }
        else if (_loginMode && EmailBox.Text.Trim().Length == 0)
        {
            ShowError(Loc.T("unlock.errEmail")); return;
        }

        Password = Pw.SecurePassword;
        Email = EmailBox.Text.Trim();
        Server = vw ? ServerBox.Text.Trim() : "";
        UseApiKey = api;
        ClientId = ClientIdBox.Text.Trim();
        ClientSecret = ClientSecretBox.SecurePassword;
        TwoFactorCode = TwoFactorBox.Text.Trim();
        TwoFactorMethod = MethodBox.SelectedIndex switch { 1 => 1, 2 => 3, _ => 0 };
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Pw_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
        else if (e.Key == Key.Escape) DialogResult = false;
    }
}
