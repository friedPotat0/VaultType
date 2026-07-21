using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using VaultType.Config;
using VaultType.Security;
using VaultType.Services;
// WinForms is in scope (UseWindowsForms), so pin these names to their WPF types.
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;
using RadioButton = System.Windows.Controls.RadioButton;
using ToggleButton = System.Windows.Controls.Primitives.ToggleButton;
using Path = System.Windows.Shapes.Path;
using Cursors = System.Windows.Input.Cursors;
using Orientation = System.Windows.Controls.Orientation;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using ColorConverter = System.Windows.Media.ColorConverter;   // vs System.Drawing.ColorConverter

namespace VaultType.Views;

// One account row shown in the settings list. App fills these in, the window edits Name/ColorHex
// and can flag a row for removal or request a brand-new account.
public sealed class AccountRow
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string ColorHex { get; set; } = AccountConfig.DefaultColor;
    public string ServerLabel { get; set; } = "";
    public bool Unlocked { get; set; }
    public bool Removed { get; set; }
}

public partial class SettingsWindow : Window
{
    private readonly AppConfig _cfg;
    private readonly bool _excludeCapture;
    private readonly string[] _langCodes;
    private readonly List<AccountRow> _rows;

    private int _uriMatch;
    private int _trayClick;
    private int _lang;
    private string? _dropdown;
    private bool _updChecking;

    public IReadOnlyList<AccountRow> AccountRows => _rows;
    public bool AddAccountRequested { get; private set; }

    // provided by App: SSH key status line and the "Schlüssel verwalten" window factory
    public Func<string>? SshStatusProvider { get; set; }
    public Func<Window?>? CreateSshWindow { get; set; }

    // provided by App: runs the sign-in dialog prefilled with the account's data ("edit vault");
    // App updates the row object with the saved values before the task completes
    public Func<AccountRow, Task>? EditAccount { get; set; }

    public SettingsWindow(AppConfig cfg, List<AccountRow> rows, bool excludeCapture)
    {
        InitializeComponent();
        _cfg = cfg;
        _rows = rows;
        _excludeCapture = excludeCapture;

        HotkeyBox.Text = cfg.Hotkey;
        DelayBox.Text = cfg.TypingDelayMs.ToString();
        IdleBox.Text = cfg.IdleTimeoutMinutes.ToString();
        ClipBox.Text = cfg.ClipboardClearSeconds.ToString();
        ClearFieldTgl.IsChecked = cfg.ClearFieldBeforeTyping;
        HideCaptureTgl.IsChecked = cfg.ExcludeFromScreenCapture;
        AntiDbgTgl.IsChecked = cfg.AntiDebugger;
        AutostartTgl.IsChecked = cfg.Autostart;
        SshAgentTgl.IsChecked = cfg.SshAgentEnabled;
        SshConfirmTgl.IsChecked = cfg.SshConfirmEachUse;
        PkProviderTgl.IsChecked = cfg.PasskeyProviderEnabled;
        PkHelloTgl.IsChecked = cfg.PasskeyRequireHello;

        // Windows only activates packaged apps as passkey plugins, so the installer/portable builds
        // can't offer the feature - grey the toggle out and say where the working edition lives.
        if (!Security.Passkey.PasskeyProvider.Supported)
        {
            PkProviderTgl.IsChecked = false;
            PkProviderTgl.IsEnabled = false;
            PkUnavailableText.Text = Loc.T(AppInfo.IsPackaged
                ? "settings.pkNeedsWin11" : "settings.pkStoreOnly");
            PkUnavailableBox.Visibility = Visibility.Visible;
        }

        _uriMatch = cfg.DefaultUriMatch;
        _trayClick = cfg.TrayClickAction;

        _langCodes = new string[Loc.Languages.Length + 1];
        _langCodes[0] = "auto";
        for (int i = 0; i < Loc.Languages.Length; i++) _langCodes[i + 1] = Loc.Languages[i].Code;
        _lang = Math.Max(0, Array.FindIndex(_langCodes, c => c.Equals(cfg.Language, StringComparison.OrdinalIgnoreCase)));

        // Store edition: the Store keeps the app current on its own; the GitHub check only
        // applies to the installer/portable builds.
        if (AppInfo.IsPackaged)
        {
            UpdStatus.Text = Loc.T("settings.updatesStore", AppInfo.Version);
            UpdBtnLabel.Text = Loc.T("settings.updatesOpenStore");
        }
        else
        {
            UpdStatus.Text = Loc.T("settings.updatesCurrent", AppInfo.Version);
            UpdBtnLabel.Text = Loc.T("settings.updatesBtn");
        }

        BuildAccounts();
        RefreshLabels();

        HotkeyBox.PreviewKeyDown += HotkeyBox_PreviewKeyDown;
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;

        NavVaults.IsChecked = true;   // open on the vaults tab
    }

    private void RefreshLabels()
    {
        UriMatchLabel.Text = UriMatchOptions[_uriMatch];
        TrayClickLabel.Text = TrayClickOptions[_trayClick];
        LangLabel.Text = LangName(_lang);
        SshAgentRows.Visibility = SshAgentTgl.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PkHelloRow.Visibility = PkProviderTgl.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        SshKeyStatus.Text = SshStatusProvider?.Invoke() ?? Loc.T("ssh.none");
    }

    private string[] UriMatchOptions => new[]
    {
        Loc.T("settings.uriMatchBase"), Loc.T("settings.uriMatchHost"), Loc.T("settings.uriMatchExact"),
    };
    private string[] TrayClickOptions => new[]
    {
        Loc.T("settings.trayClickMenu"), Loc.T("settings.trayClickAutotype"), Loc.T("settings.trayClickSettings"),
    };
    private string LangName(int idx) => idx == 0 ? Loc.T("settings.langAuto") : Loc.Languages[idx - 1].Name;

    // Sidebar navigation: show the panel matching the picked entry.
    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (PanelVaults == null || sender is not RadioButton rb) return;   // not built yet
        string tab = rb.Tag as string ?? "vaults";
        PanelVaults.Visibility = tab == "vaults" ? Visibility.Visible : Visibility.Collapsed;
        PanelAutoType.Visibility = tab == "autotype" ? Visibility.Visible : Visibility.Collapsed;
        PanelSecurity.Visibility = tab == "security" ? Visibility.Visible : Visibility.Collapsed;
        PanelIntegration.Visibility = tab == "integration" ? Visibility.Visible : Visibility.Collapsed;
        PanelGeneral.Visibility = tab == "general" ? Visibility.Visible : Visibility.Collapsed;
        CloseDropdown();
        ContentScroll?.ScrollToTop();
    }

    // Dev-only (gallery/screenshot mode): render the passkey rows as if the plugin were available,
    // so the mock captures don't show the unpackaged-build hint.
    internal void ShowPasskeyAsSupported()
    {
        PkProviderTgl.IsEnabled = true;
        PkProviderTgl.IsChecked = _cfg.PasskeyProviderEnabled;
        PkUnavailableBox.Visibility = Visibility.Collapsed;
        RefreshLabels();
    }

    private void SshAgent_Toggled(object sender, RoutedEventArgs e) { if (SshAgentRows != null) RefreshLabels(); }
    private void PkProvider_Toggled(object sender, RoutedEventArgs e) { if (PkHelloRow != null) RefreshLabels(); }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
    }

    // ---- vault list ----

    private void BuildAccounts()
    {
        AccountsPanel.Children.Clear();
        foreach (var row in _rows)
        {
            if (row.Removed) continue;
            AccountsPanel.Children.Add(MakeAccountRow(row));
        }
    }

    // design row: avatar 34 (radius 9, gradient) | name 13 semibold + server 11.5 | pencil + trash
    private FrameworkElement MakeAccountRow(AccountRow row)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var avatarText = new TextBlock
        {
            Text = Initial(row.Name), Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xF8)),
            FontSize = 13, FontWeight = FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
        };
        var avatar = new Border
        {
            Width = 34, Height = 34, CornerRadius = new CornerRadius(9), VerticalAlignment = VerticalAlignment.Center,
            Background = Gradient(row.ColorHex), Child = avatarText, Cursor = Cursors.Hand,
        };
        // clicking the avatar cycles the palette colour (same affordance as the sign-in dialog)
        avatar.MouseLeftButtonDown += (_, __) =>
        {
            int idx = Array.IndexOf(AccountConfig.Palette, row.ColorHex);
            row.ColorHex = AccountConfig.Palette[(idx + 1) % AccountConfig.Palette.Length];
            avatar.Background = Gradient(row.ColorHex);
        };
        Grid.SetColumn(avatar, 0);

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var nameText = new TextBlock
        {
            Text = row.Name, Foreground = (Brush)FindResource("TextBody"),
            FontSize = 13, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis,
            Cursor = Cursors.IBeam, ToolTip = Loc.T("settings.editVault"),
        };
        // clicking the name switches to a small inline editor; Enter / focus-out commits, Esc cancels
        var nameEdit = new Border
        {
            Style = (Style)FindResource("SmallFieldBorder"), Height = 28, Visibility = Visibility.Collapsed,
            Margin = new Thickness(0, 0, 0, 1),
        };
        var nameBox = new TextBox { Style = (Style)FindResource("PlainBox"), FontSize = 13, Margin = new Thickness(9, 0, 9, 0) };
        nameEdit.Child = nameBox;
        void CloseNameEdit()
        {
            nameEdit.Visibility = Visibility.Collapsed;
            nameText.Visibility = Visibility.Visible;
        }
        void CommitName()
        {
            string t = nameBox.Text.Trim();
            if (t.Length > 0) { row.Name = t; nameText.Text = t; avatarText.Text = Initial(t); }
            CloseNameEdit();
        }
        nameText.MouseLeftButtonDown += (_, e) =>
        {
            e.Handled = true;   // don't let the window's DragMove swallow the click
            nameBox.Text = row.Name;
            nameText.Visibility = Visibility.Collapsed;
            nameEdit.Visibility = Visibility.Visible;
            nameBox.Focus();
            nameBox.SelectAll();
        };
        nameBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) { CommitName(); e.Handled = true; }
            else if (e.Key == Key.Escape) { CloseNameEdit(); e.Handled = true; }
        };
        nameBox.LostKeyboardFocus += (_, __) => { if (nameEdit.Visibility == Visibility.Visible) CommitName(); };
        var server = new TextBlock
        {
            Text = row.ServerLabel, Foreground = (Brush)FindResource("TextHint"), FontSize = 11.5,
            Margin = new Thickness(0, 1, 0, 0), TextTrimming = TextTrimming.CharacterEllipsis,
        };
        texts.Children.Add(nameText);
        texts.Children.Add(nameEdit);
        texts.Children.Add(server);
        Grid.SetColumn(texts, 2);

        var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var edit = new Button { Style = (Style)FindResource("FlatIconButton"), ToolTip = Loc.T("settings.editVault") };
        edit.Content = Glyph("IconPencil", 15);
        edit.Click += async (_, __) =>
        {
            // open the sign-in dialog prefilled with this vault's data; App updates the row on save
            if (EditAccount == null) return;
            await EditAccount(row);
            BuildAccounts();
        };
        var remove = new Button { Style = (Style)FindResource("FlatIconButtonDanger"), ToolTip = Loc.T("settings.removeVault"), Margin = new Thickness(2, 0, 0, 0) };
        remove.Content = Glyph("IconTrash", 16);
        remove.Click += (_, __) => RemoveRow(row);
        actions.Children.Add(edit);
        actions.Children.Add(remove);
        Grid.SetColumn(actions, 3);

        grid.Children.Add(avatar);
        grid.Children.Add(texts);
        grid.Children.Add(actions);
        return grid;
    }

    private FrameworkElement Glyph(string key, double size)
    {
        var canvas = new Canvas { Width = 24, Height = 24 };
        canvas.Children.Add(new Path
        {
            Data = (Geometry)FindResource(key),
            Stroke = new SolidColorBrush(Colors.White) { Opacity = 0 },   // placeholder, replaced below
        });
        // stroke follows the button foreground so hover recolours the glyph
        var path = (Path)canvas.Children[0];
        path.SetBinding(System.Windows.Shapes.Shape.StrokeProperty,
            new System.Windows.Data.Binding("Foreground") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(Button), 1) });
        path.StrokeThickness = 1.7;
        path.StrokeStartLineCap = PenLineCap.Round;
        path.StrokeEndLineCap = PenLineCap.Round;
        path.StrokeLineJoin = PenLineJoin.Round;
        return new Viewbox { Width = size, Height = size, Child = canvas };
    }

    private static string Initial(string name)
    {
        string t = name.Trim();
        return t.Length > 0 ? t[..1].ToUpperInvariant() : "?";
    }

    private static Brush Gradient(string hex)
    {
        try
        {
            var c = (Color)ColorConverter.ConvertFromString(hex);
            var dark = Color.FromRgb((byte)(c.R * 0.62), (byte)(c.G * 0.62), (byte)(c.B * 0.62));
            var b = new LinearGradientBrush(c, dark, new Point(0.12, 0), new Point(0.88, 1));
            b.Freeze();
            return b;
        }
        catch { return Brushes.Gray; }
    }

    private void RemoveRow(AccountRow row)
    {
        var confirm = new ConfirmWindow(Loc.T("settings.removeTitle"), Loc.T("settings.removeMsg", row.Name), _excludeCapture);
        if (confirm.ShowDialog() != true) return;
        row.Removed = true;
        BuildAccounts();
    }

    private void AddAccount_Click(object sender, RoutedEventArgs e)
    {
        AddAccountRequested = true;
        DialogResult = true;
    }

    // ---- dropdowns (overlay panels) ----

    private void Dropdown_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton trigger) return;
        trigger.IsChecked = false;
        string which = trigger.Tag as string ?? "";
        if (_dropdown == which) { CloseDropdown(); return; }
        _dropdown = which;
        DropdownItems.Children.Clear();

        (string[] options, int current, Action<int> pick) = which switch
        {
            "urimatch" => (UriMatchOptions, _uriMatch, (Action<int>)(i => { _uriMatch = i; RefreshLabels(); })),
            "trayclick" => (TrayClickOptions, _trayClick, i => { _trayClick = i; RefreshLabels(); }),
            _ => (Enumerable.Range(0, _langCodes.Length).Select(LangName).ToArray(), _lang, i => { _lang = i; RefreshLabels(); }),
        };
        for (int i = 0; i < options.Length; i++)
        {
            if (i == current) continue;   // the design lists only the other options
            int idx = i;
            var rowBtn = new Button
            {
                Style = (Style)FindResource("DropdownRow"),
                Content = new TextBlock { Text = options[i], Foreground = (Brush)FindResource("TextBody"), FontSize = 13 },
            };
            // compact rows for the settings variant (design: padding 8px 11px, radius 9)
            rowBtn.Margin = new Thickness(0, 1, 0, 1);
            rowBtn.Click += (_, __) => { pick(idx); CloseDropdown(); };
            DropdownItems.Children.Add(rowBtn);
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

    private void Backdrop_Click(object sender, MouseButtonEventArgs e) => CloseDropdown();

    private void CloseDropdown()
    {
        _dropdown = null;
        if (Overlay != null) Overlay.Visibility = Visibility.Collapsed;
    }

    // ---- SSH keys ----

    private void SshManage_Click(object sender, RoutedEventArgs e)
    {
        var win = CreateSshWindow?.Invoke();
        if (win == null) return;
        win.Owner = this;
        win.ShowDialog();
        RefreshLabels();
    }

    // ---- updates ----

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        if (AppInfo.IsPackaged)
        {
            try
            {
                System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo(AppInfo.StoreUri) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                UpdStatus.Text = ex.Message;
            }
            return;
        }
        if (_updChecking) return;
        _updChecking = true;
        UpdStatus.Text = Loc.T("settings.updatesChecking");
        UpdBtnLabel.Text = Loc.T("settings.updatesBtnChecking");
        try
        {
            var info = await UpdateService.CheckAsync(AppInfo.Version);
            UpdStatus.Text = info == null ? Loc.T("msg.updateFailed")
                : info.IsNewer ? Loc.T("settings.updatesAvailable", info.LatestVersion)
                : Loc.T("settings.updatesUpToDate");
        }
        catch
        {
            // async void: swallow so the status never gets stuck on "checking…" and no unhandled
            // exception escapes to the dispatcher.
            UpdStatus.Text = Loc.T("msg.updateFailed");
        }
        finally
        {
            _updChecking = false;
            UpdBtnLabel.Text = Loc.T("settings.updatesBtn");
        }
    }

    // Capture a key combination directly instead of typing it.
    private void HotkeyBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        e.Handled = true;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;

        if (key is Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt
            or Key.LeftShift or Key.RightShift or Key.LWin or Key.RWin or Key.System or Key.None)
            return;
        if (key == Key.Escape) return;

        var mods = Keyboard.Modifiers;
        bool isFunctionKey = key >= Key.F1 && key <= Key.F24;
        if (mods == ModifierKeys.None && !isFunctionKey) return; // require a modifier for normal keys

        var parts = new List<string>();
        if (mods.HasFlag(ModifierKeys.Control)) parts.Add("Ctrl");
        if (mods.HasFlag(ModifierKeys.Alt)) parts.Add("Alt");
        if (mods.HasFlag(ModifierKeys.Shift)) parts.Add("Shift");
        if (mods.HasFlag(ModifierKeys.Windows)) parts.Add("Win");
        parts.Add(key.ToString());

        HotkeyBox.Text = string.Join("+", parts);
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (HotkeyBox.Text.Trim().Length > 0) _cfg.Hotkey = HotkeyBox.Text.Trim();
        _cfg.TypingDelayMs = ParseInt(DelayBox.Text, _cfg.TypingDelayMs, 0, 500);
        _cfg.IdleTimeoutMinutes = ParseInt(IdleBox.Text, _cfg.IdleTimeoutMinutes, 0, 1440);
        _cfg.ClipboardClearSeconds = ParseInt(ClipBox.Text, _cfg.ClipboardClearSeconds, 0, 3600);
        _cfg.ClearFieldBeforeTyping = ClearFieldTgl.IsChecked == true;
        _cfg.ExcludeFromScreenCapture = HideCaptureTgl.IsChecked == true;
        _cfg.AntiDebugger = AntiDbgTgl.IsChecked == true;
        _cfg.Autostart = AutostartTgl.IsChecked == true;
        AutostartService.Set(_cfg.Autostart);

        _cfg.SshAgentEnabled = SshAgentTgl.IsChecked == true;
        _cfg.SshConfirmEachUse = SshConfirmTgl.IsChecked == true;
        // A disabled toggle means "can't work here", not "off" - keep the stored value so the
        // setting survives a round trip through an unpackaged build (the config file is shared).
        if (PkProviderTgl.IsEnabled)
            _cfg.PasskeyProviderEnabled = PkProviderTgl.IsChecked == true;
        _cfg.PasskeyRequireHello = PkHelloTgl.IsChecked == true;

        _cfg.DefaultUriMatch = _uriMatch;
        _cfg.TrayClickAction = _trayClick;
        _cfg.EnableTrayClick = _trayClick == 1;   // the foreground hook is only needed for auto-type
        _cfg.Language = _langCodes[Math.Clamp(_lang, 0, _langCodes.Length - 1)];

        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static int ParseInt(string text, int fallback, int min, int max)
        => int.TryParse(text.Trim(), out int v) ? Math.Clamp(v, min, max) : fallback;
}
