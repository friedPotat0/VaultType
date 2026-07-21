using System.Linq;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;
using Button = System.Windows.Controls.Button;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace VaultType.Views;

// One account offered by the unlock window's switcher.
public sealed class AccountChoice
{
    public string Id = "";
    public string Name = "";
    public string Email = "";
    public string Server = "";
    public string ColorHex = "";
}

// The unlock dialog (unlock only - signing in lives in SignInWindow). The visible input follows
// the account's preferred unlock method: master password, PIN, Windows Hello or passkey.
public partial class UnlockWindow : Window
{
    public SecureString? Password { get; private set; }   // master password (method = password)
    public SecureString? Pin { get; private set; }        // PIN (method = pin)

    private readonly bool _excludeCapture;
    private readonly string _method;
    private List<AccountChoice> _accounts = new();
    private int _selIndex;

    // the account the user chose in the switcher (null if no switcher was used)
    public string? SelectedAccountId { get; private set; }

    // fires when the user picks a different account in the switcher (so the caller can swap the
    // visible unlock method to that account's preference)
    public event Action<string>? AccountPicked;

    public UnlockWindow(string heading, string subtitle, bool excludeCapture, string method = "password")
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        _method = method;

        if (!string.IsNullOrEmpty(heading)) Heading.Text = heading;
        Subtitle.Text = !string.IsNullOrEmpty(subtitle) ? subtitle : Loc.T(method switch
        {
            "pin" => "unlock.hintPin",
            "bio" => "unlock.hintBio",
            "passkey" => "unlock.hintPasskey",
            _ => "unlock.hintPassword",
        });

        PasswordGroup.Visibility = method == "password" ? Visibility.Visible : Visibility.Collapsed;
        PinGroup.Visibility = method == "pin" ? Visibility.Visible : Visibility.Collapsed;
        OkLabel.Text = Loc.T(method switch
        {
            "bio" => "unlock.btnBio",
            "passkey" => "unlock.btnPasskey",
            _ => "unlock.btnUnlock",
        });

        Pw.PasswordChanged += (_, __) => PwPlaceholder.Visibility = Pw.SecurePassword.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        PinBox.PasswordChanged += (_, __) => PinPlaceholder.Visibility = PinBox.SecurePassword.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        PwPlaceholder.Visibility = Visibility.Visible;
        PinPlaceholder.Visibility = Visibility.Visible;

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        var h = new WindowInteropHelper(this).Handle;
        if (_excludeCapture)
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);

        // The dialog usually opens while another app is foreground (hotkey, SSH/passkey request).
        // Windows then refuses a plain Activate(), so the master password would land in the old
        // window. Steal the foreground properly: attach to the foreground thread's input queue.
        ForceForeground(h);
        FocusInput();
        // Some openers re-assert their foreground state right after; focus again on the next
        // dispatcher turn so the keyboard focus reliably ends up in the input field.
        Dispatcher.BeginInvoke((Action)(() => { ForceForeground(h); FocusInput(); }),
            System.Windows.Threading.DispatcherPriority.Input);
    }

    private void ForceForeground(IntPtr hwnd)
    {
        try
        {
            IntPtr fg = Native.GetForegroundWindow();
            if (fg == hwnd) { Activate(); return; }
            uint fgThread = Native.GetWindowThreadProcessId(fg, out _);
            uint myThread = Native.GetCurrentThreadId();
            bool attached = fg != IntPtr.Zero && fgThread != myThread
                && Native.AttachThreadInput(myThread, fgThread, true);
            try
            {
                Native.SetForegroundWindow(hwnd);
                Activate();
            }
            finally { if (attached) Native.AttachThreadInput(myThread, fgThread, false); }
            // last resort: a brief topmost pulse forces the window above everything
            if (Native.GetForegroundWindow() != hwnd) { Topmost = true; Topmost = false; Activate(); }
        }
        catch { }
    }

    private void FocusInput()
    {
        if (_method == "pin") { PinBox.Focus(); Keyboard.Focus(PinBox); }
        else { Pw.Focus(); Keyboard.Focus(Pw); }
    }

    public void ShowError(string message)
    {
        Error.Text = message;
        Error.Visibility = Visibility.Visible;
        Pw.Clear();
        PinBox.Clear();
        if (_method == "pin") PinBox.Focus(); else Pw.Focus();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (_method == "password" && Pw.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errMaster")); return; }
        if (_method == "pin" && PinBox.SecurePassword.Length == 0) { ShowError(Loc.T("unlock.errPin")); return; }
        // Only hand back the field for the active method; leaving the other null avoids an unused,
        // never-disposed SecureString (the caller only reads/disposes the one matching the method).
        if (_method == "pin") Pin = PinBox.SecurePassword;
        else Password = Pw.SecurePassword;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Pw_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
        else if (e.Key == Key.Escape) Cancel_Click(sender, e);
    }

    // ---- account row + switcher ----

    // Populate the switcher with all configured accounts; the selected one fills the row. When
    // more than one account exists the row gains a chevron and opens the switcher dropdown.
    public void SetAccounts(IReadOnlyList<AccountChoice> accounts, int selectedIndex)
    {
        _accounts = accounts.ToList();
        if (_accounts.Count == 0) return;
        _selIndex = Math.Clamp(selectedIndex, 0, _accounts.Count - 1);
        var sel = _accounts[_selIndex];
        SelectedAccountId = sel.Id;
        ShowAccount(sel.Name, sel.Email, sel.Server, sel.ColorHex);
        AccountArea.Visibility = Visibility.Visible;
        ChipChevron.Visibility = _accounts.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        BuildSwitcherItems();
    }

    private void ShowAccount(string name, string email, string server, string? colorHex)
    {
        // The design shows the vault's display name (bold) over the server, with a gradient avatar.
        string display = !string.IsNullOrWhiteSpace(name) ? name : email;
        AvatarText.Text = !string.IsNullOrWhiteSpace(name) ? InitialsForName(name) : Initials(email);
        Color baseColor = !string.IsNullOrEmpty(colorHex)
            ? (Color)ColorConverter.ConvertFromString(colorHex)
            : ((SolidColorBrush)new AvatarBrushConverter().Convert(display, typeof(Brush), null!, System.Globalization.CultureInfo.InvariantCulture)).Color;
        AvatarBorder.Background = AvatarGradient(baseColor);
        ChipEmail.Text = display;
        ChipServer.Text = ServerHost(server);
    }

    // A vault name maps to a single initial (single word) or two (multi-word), matching the design.
    private static string InitialsForName(string name)
    {
        var tokens = name.Trim().Split(new[] { ' ', '-', '_' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return "?";
        return (tokens.Length >= 2 ? string.Concat(tokens[0][0], tokens[1][0]) : tokens[0][..1]).ToUpperInvariant();
    }

    // A top-left-light to bottom-right-dark gradient from a base colour (matches the design avatars).
    private static Brush AvatarGradient(Color c)
    {
        var dark = Color.FromRgb((byte)(c.R * 0.62), (byte)(c.G * 0.62), (byte)(c.B * 0.62));
        return new System.Windows.Media.LinearGradientBrush(c, dark, new Point(0.12, 0), new Point(0.88, 1));
    }

    private void Chip_Click(object sender, RoutedEventArgs e)
    {
        if (_accounts.Count <= 1) return;
        if (Overlay.Visibility == Visibility.Visible) CloseSwitcher();
        else OpenSwitcher();
    }

    // Open the switcher as a dropdown that overlays the content (positioned under the account row),
    // so the window keeps its size instead of growing.
    public void OpenSwitcher()
    {
        Overlay.Visibility = Visibility.Visible;
        Overlay.UpdateLayout();
        var p = AccountChip.TranslatePoint(new Point(0, AccountChip.ActualHeight + 6), Overlay);
        Canvas.SetTop(SwitcherMenu, p.Y);
        SwitcherMenu.Width = Math.Max(80, Overlay.ActualWidth - 44);
        // never taller than the window: cap the menu and let its ScrollViewer take over
        SwitcherMenu.MaxHeight = Math.Max(80, Overlay.ActualHeight - p.Y - 8);
    }

    private void CloseSwitcher() => Overlay.Visibility = Visibility.Collapsed;

    private void Backdrop_Click(object sender, MouseButtonEventArgs e) => CloseSwitcher();

    // The dropdown lists only the *other* accounts (the selected one sits in the row above it).
    private void BuildSwitcherItems()
    {
        SwitcherItems.Children.Clear();
        for (int i = 0; i < _accounts.Count; i++)
        {
            if (i == _selIndex) continue;
            int idx = i;
            var row = new Button { Style = (Style)FindResource("DropdownRow"), Content = BuildRow(_accounts[i]) };
            row.Click += (_, __) => Select(idx);
            SwitcherItems.Children.Add(row);
        }
    }

    private FrameworkElement BuildRow(AccountChoice a)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        string display = !string.IsNullOrWhiteSpace(a.Name) ? a.Name : a.Email;
        string init = !string.IsNullOrWhiteSpace(a.Name) ? InitialsForName(a.Name) : Initials(a.Email);
        Color baseColor = string.IsNullOrEmpty(a.ColorHex)
            ? ((SolidColorBrush)new AvatarBrushConverter().Convert(display, typeof(Brush), null!, System.Globalization.CultureInfo.InvariantCulture)).Color
            : (Color)ColorConverter.ConvertFromString(a.ColorHex);
        var avatar = new Border
        {
            Width = 32, Height = 32, CornerRadius = new CornerRadius(9), VerticalAlignment = System.Windows.VerticalAlignment.Center,
            Background = AvatarGradient(baseColor),
            Child = new TextBlock { Text = init, Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xF8)), FontSize = 12.5, FontWeight = FontWeights.Bold, HorizontalAlignment = System.Windows.HorizontalAlignment.Center, VerticalAlignment = System.Windows.VerticalAlignment.Center },
        };
        Grid.SetColumn(avatar, 0);

        var texts = new StackPanel { VerticalAlignment = System.Windows.VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
        texts.Children.Add(new TextBlock { Text = display, Foreground = (Brush)FindResource("TextBody"), FontSize = 13.5, FontWeight = FontWeights.SemiBold });
        texts.Children.Add(new TextBlock { Text = ServerHost(a.Server), Foreground = (Brush)FindResource("TextSecondary"), FontSize = 12.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 1, 0, 0) });
        Grid.SetColumn(texts, 1);

        grid.Children.Add(avatar);
        grid.Children.Add(texts);
        return grid;
    }

    private void Select(int index)
    {
        _selIndex = index;
        var a = _accounts[index];
        SelectedAccountId = a.Id;
        ShowAccount(a.Name, a.Email, a.Server, a.ColorHex);
        CloseSwitcher();
        BuildSwitcherItems();
        AccountPicked?.Invoke(a.Id);
        if (_method == "pin") PinBox.Focus(); else Pw.Focus();
    }

    // ---- helpers ----

    // Generic mailboxes make poor personal initials, so fall back to the domain for them.
    private static readonly HashSet<string> RoleWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "info", "admin", "administrator", "support", "contact", "hello", "hi", "mail", "email",
        "office", "sales", "help", "team", "service", "services", "webmaster", "root", "user",
        "account", "accounts", "billing", "security", "noreply", "no-reply", "donotreply",
        "do-not-reply", "postmaster", "abuse", "hostmaster", "kontakt",
    };

    // Best-effort initials from the (server-official) email. A name-like local part gives personal
    // initials (alex.doe -> AD); a role mailbox falls back to the domain (info@acme.io -> AC).
    internal static string Initials(string email)
    {
        string e = email.Trim();
        int at = e.IndexOf('@');
        string local = at > 0 ? e[..at] : e;
        string domain = at >= 0 && at < e.Length - 1 ? e[(at + 1)..] : "";
        var tokens = local.Split(new[] { '.', '_', '-', '+', ' ' }, StringSplitOptions.RemoveEmptyEntries);

        string s;
        if (tokens.Length >= 2) s = string.Concat(tokens[0][0], tokens[1][0]);          // alex.doe -> AD
        else if (tokens.Length == 1 && !RoleWords.Contains(tokens[0]))
            s = tokens[0].Length >= 2 ? tokens[0][..2] : tokens[0];                      // christian -> CH
        else s = DomainInitials(domain);                                                // info -> domain
        if (s.Length == 0) s = e.Length > 0 ? e[..1] : "?";
        return s.ToUpperInvariant();
    }

    private static string DomainInitials(string domain)
    {
        var parts = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return "";
        string main = parts.Length >= 2 ? parts[^2] : parts[0];   // example.com -> example
        return main.Length >= 2 ? main[..2] : main;
    }

    internal static string ServerHost(string url)
    {
        string r = url ?? "";
        int i = r.IndexOf("://", StringComparison.Ordinal);
        if (i >= 0) r = r[(i + 3)..];
        int s = r.IndexOfAny(new[] { '/', '?', '#' });
        if (s >= 0) r = r[..s];
        return r;
    }
}
