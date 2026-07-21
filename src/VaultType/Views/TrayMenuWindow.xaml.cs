using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using VaultType.Security;
using VaultType.Services;
using Button = System.Windows.Controls.Button;
using Orientation = System.Windows.Controls.Orientation;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Path = System.Windows.Shapes.Path;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace VaultType.Views;

// The design "TrayMenu": a 274px frameless popup shown at the tray. Account rows plus the
// standard actions; closes on deactivation. All actions run through the callbacks App passes in.
public partial class TrayMenuWindow : Window
{
    public sealed class Actions
    {
        public Action<VaultSession>? SelectAccount;
        public Action? AutoType;
        public Action? Sync;
        public Action<VaultSession>? LockOne;
        public Action? LockAll;
        public Action? CheckUpdates;
        public Action? OpenSettings;
        public Action? Exit;
    }

    private readonly IReadOnlyList<VaultSession> _sessions;
    private readonly Actions _actions;
    private readonly string _hotkey;
    private bool _closing;
    private readonly string _syncHint;
    private readonly bool _excludeCapture;

    // The action the user picked; App runs it in the Closed handler, once this window is fully gone
    // (calling Show/ShowDialog while a window is still closing throws).
    public Action? PendingAction { get; private set; }

    public TrayMenuWindow(IReadOnlyList<VaultSession> sessions, string hotkey, string syncHint, Actions actions,
        bool excludeCapture = false)
    {
        InitializeComponent();
        _sessions = sessions;
        _actions = actions;
        _hotkey = hotkey;
        _syncHint = syncHint;
        _excludeCapture = excludeCapture;
        Build();
        // Close when focus moves elsewhere. Deactivated fires INSIDE the WM_ACTIVATE window
        // procedure; calling Close() synchronously there tears the window down from within its own
        // WndProc, and any exception raised during that teardown crosses the native callback
        // boundary as STATUS_FATAL_USER_CALLBACK_EXCEPTION - an uncatchable process kill (seen when
        // an SSH-agent unlock/confirm dialog stole focus from an open tray menu). Defer the close
        // onto the dispatcher so it runs after WmActivate returns, and guard against re-entry.
        Deactivated += (_, __) =>
        {
            if (_closing) return;
            _closing = true;
            Dispatcher.BeginInvoke(new Action(() => { try { Close(); } catch { } }));
        };
    }

    private bool AnyUnlocked => _sessions.Any(s => s.Unlocked);

    private void Build()
    {
        Root.Children.Clear();

        // account rows
        foreach (var s in _sessions) Root.Children.Add(AccountRow(s));
        if (_sessions.Count > 0) Root.Children.Add(Divider());

        Root.Children.Add(ActionRow("IconKeyboard", Loc.T("tray.autotype"), _hotkey, () => _actions.AutoType?.Invoke()));
        Root.Children.Add(ActionRow("IconSync", Loc.T("tray.sync"), _syncHint, () => _actions.Sync?.Invoke()));

        if (AnyUnlocked)
        {
            Root.Children.Add(Divider());
            var active = _sessions.FirstOrDefault(s => s.Unlocked);
            if (active != null)
                Root.Children.Add(ActionRow("IconLock", Loc.T("tray.lockOne", active.Cfg.Name), null, () => _actions.LockOne?.Invoke(active)));
            Root.Children.Add(ActionRow("IconLock", Loc.T("tray.lockAll"), null, () => _actions.LockAll?.Invoke()));
        }

        Root.Children.Add(Divider());
        // Store edition: the action opens the Store product page, so say that instead of "check".
        Root.Children.Add(ActionRow("IconDownload",
            Loc.T(AppInfo.IsPackaged ? "settings.updatesOpenStore" : "tray.checkUpdates"),
            null, () => _actions.CheckUpdates?.Invoke()));
        Root.Children.Add(ActionRow("IconSliders", Loc.T("tray.settings"), null, () => _actions.OpenSettings?.Invoke()));
        Root.Children.Add(ActionRow("IconPower", Loc.T("tray.exit"), null, () => _actions.Exit?.Invoke()));
    }

    // design account row: 28px avatar (radius 8), name 13 semibold + server 11, right = count or lock
    private FrameworkElement AccountRow(VaultSession s)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var avatar = new Border
        {
            Width = 28, Height = 28, CornerRadius = new CornerRadius(8), VerticalAlignment = VerticalAlignment.Center,
            Background = Gradient(s.Cfg.ColorHex),
            Child = new TextBlock
            {
                Text = Initial(s.Cfg.Name), Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xF8)),
                FontSize = 12, FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            },
        };
        Grid.SetColumn(avatar, 0);

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = s.Cfg.Name, Foreground = (Brush)FindResource("TextBody"), FontSize = 13, FontWeight = FontWeights.SemiBold });
        texts.Children.Add(new TextBlock { Text = ServerLabel(s), Foreground = (Brush)FindResource("TextHint"), FontSize = 11, Margin = new Thickness(0, 1, 0, 0) });
        Grid.SetColumn(texts, 2);

        FrameworkElement right;
        if (s.Unlocked)
            right = new TextBlock { Text = Loc.T("tray.entries", s.Items.Count), Foreground = (Brush)FindResource("TextMuted"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
        else
            right = new Viewbox { Width = 14, Height = 14, VerticalAlignment = VerticalAlignment.Center, Child = StrokeCanvas("IconLock", (Brush)FindResource("TextMuted"), 1.9) };
        Grid.SetColumn(right, 3);

        grid.Children.Add(avatar);
        grid.Children.Add(texts);
        grid.Children.Add(right);

        // An unlocked vault has no click action, so its row is a plain (non-hoverable) entry;
        // a locked row stays clickable and triggers the unlock flow.
        if (s.Unlocked)
            return new Border { Child = grid, Padding = new Thickness(13, 8, 11, 8) };
        return Hoverable(grid, new Thickness(13, 8, 11, 8), () => _actions.SelectAccount?.Invoke(s));
    }

    // design menu item: icon 15 + label + optional right hint, hover faint white
    private FrameworkElement ActionRow(string icon, string label, string? hint, Action onClick)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(11) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var iconBox = new Viewbox { Width = 15, Height = 15, VerticalAlignment = VerticalAlignment.Center, Child = StrokeCanvas(icon, (Brush)FindResource("TextSecondary"), 1.7) };
        Grid.SetColumn(iconBox, 0);
        var text = new TextBlock { Text = label, Foreground = (Brush)FindResource("TextBody"), FontSize = 13, VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(text, 2);
        grid.Children.Add(iconBox);
        grid.Children.Add(text);
        if (!string.IsNullOrEmpty(hint))
        {
            var h = new TextBlock { Text = hint, Foreground = (Brush)FindResource("TextMuted"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(h, 3);
            grid.Children.Add(h);
        }
        return Hoverable(grid, new Thickness(10, 8, 10, 8), onClick);
    }

    private Button Hoverable(UIElement content, Thickness padding, Action onClick)
    {
        var border = new Border { Child = content, CornerRadius = new CornerRadius(8), Padding = padding, Background = Brushes.Transparent };
        var btn = new Button { Content = border, Cursor = System.Windows.Input.Cursors.Hand, HorizontalContentAlignment = HorizontalAlignment.Stretch };
        btn.Template = TransparentButtonTemplate();
        var hover = new SolidColorBrush(Color.FromArgb(0x0F, 0xFF, 0xFF, 0xFF));
        border.MouseEnter += (_, __) => border.Background = hover;
        border.MouseLeave += (_, __) => border.Background = Brushes.Transparent;
        // Record the choice and close; App invokes it from the Closed handler (after this window is
        // fully torn down) so opening the next dialog never races the closing menu.
        btn.Click += (_, __) => { PendingAction = onClick; _closing = true; Close(); };
        return btn;
    }

    private static ControlTemplate TransparentButtonTemplate()
    {
        var t = new ControlTemplate(typeof(Button));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        t.VisualTree = presenter;
        return t;
    }

    private FrameworkElement Divider() => new Border
    {
        Height = 1, Background = new SolidColorBrush(Color.FromArgb(0x14, 0xFF, 0xFF, 0xFF)),
        Margin = new Thickness(6, 5, 6, 5),
    };

    private Canvas StrokeCanvas(string key, Brush stroke, double thickness)
    {
        var canvas = new Canvas { Width = 24, Height = 24 };
        canvas.Children.Add(new Path
        {
            Data = (Geometry)FindResource(key), Stroke = stroke, StrokeThickness = thickness,
            StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round,
        });
        return canvas;
    }

    private static string ServerLabel(VaultSession s) => s.Cfg.Kind switch
    {
        Config.AccountKind.BitwardenUS => "Bitwarden (US)",
        Config.AccountKind.BitwardenEU => "Bitwarden (EU)",
        _ => UnlockWindow.ServerHost(s.Cfg.ServerUrl),
    };

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

    // Show with the menu's bottom-right corner near the given screen point (like a real tray menu).
    public void ShowAt(double screenX, double screenY)
    {
        WindowStartupLocation = WindowStartupLocation.Manual;
        Show();
        // Keep the menu (account names, servers, entry counts) out of screen captures, like every
        // other window, when the option is on. The handle exists only after Show().
        if (_excludeCapture)
            Native.SetWindowDisplayAffinity(new WindowInteropHelper(this).Handle, Native.WDA_EXCLUDEFROMCAPTURE);
        UpdateLayout();
        double dpi = VisualTreeHelper.GetDpi(this).DpiScaleX;
        if (dpi <= 0) dpi = 1;
        Left = screenX / dpi - ActualWidth + 12;   // +12 offsets the transparent margin
        Top = screenY / dpi - ActualHeight + 12;
        Activate();
    }
}
