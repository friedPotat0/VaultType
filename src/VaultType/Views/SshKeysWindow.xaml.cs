using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using VaultType.Config;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;
using Button = System.Windows.Controls.Button;
using ToggleButton = System.Windows.Controls.Primitives.ToggleButton;
using Path = System.Windows.Shapes.Path;
using Orientation = System.Windows.Controls.Orientation;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace VaultType.Views;

// Design "SSH - Schlüssel verwalten": every SSH key from the unlocked vaults, with a copy button
// and an "im Agent laden" toggle per key. Toggles persist into AppConfig.SshDisabledKeys.
public partial class SshKeysWindow : Window
{
    private readonly AppConfig _cfg;
    private readonly List<(VaultSession Session, SshKeyEntry Key)> _keys;
    private readonly bool _anyUnlocked;

    public SshKeysWindow(IReadOnlyList<VaultSession> sessions, AppConfig cfg, bool excludeCapture)
    {
        InitializeComponent();
        _cfg = cfg;
        _keys = sessions.Where(s => s.Unlocked)
                        .SelectMany(s => s.SshKeys.Select(k => (s, k)))
                        .ToList();

        // Tell "locked" apart from "unlocked but the vault holds no SSH keys".
        _anyUnlocked = sessions.Any(s => s.Unlocked);
        if (_anyUnlocked)
        {
            EmptyTitle.Text = Loc.T("ssh.noKeysTitle");
            EmptyMsg.Text = Loc.T("ssh.noKeysMsg");
        }

        BuildList();
        RefreshStatus();

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        if (excludeCapture)
            Loaded += (_, __) =>
            {
                var h = new WindowInteropHelper(this).Handle;
                Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
            };
    }

    // Status line for the settings row and this window's header.
    public static string StatusText(IEnumerable<VaultSession> sessions)
    {
        if (!sessions.Any(s => s.Unlocked)) return Loc.T("ssh.none");
        int n = sessions.Where(s => s.Unlocked).Sum(s => s.SshKeys.Count);
        if (n == 0) return Loc.T("ssh.noKeysTitle");
        return n == 1 ? Loc.T("ssh.one") : Loc.T("ssh.many", n);
    }

    private void BuildList()
    {
        KeyList.Children.Clear();
        EmptyState.Visibility = _keys.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var (session, key) in _keys)
            KeyList.Children.Add(MakeRow(session, key));
    }

    // design row: icon tile 34 | name + type chip / fingerprint / vault badge | copy + toggle
    private FrameworkElement MakeRow(VaultSession session, SshKeyEntry key)
    {
        var row = new Border { CornerRadius = new CornerRadius(11), Padding = new Thickness(10), Background = Brushes.Transparent };
        row.MouseEnter += (_, __) => row.Background = (Brush)FindResource("Field");
        row.MouseLeave += (_, __) => row.Background = Brushes.Transparent;

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        // key icon tile
        var iconCanvas = new Canvas { Width = 24, Height = 24 };
        iconCanvas.Children.Add(new Path
        {
            Data = (Geometry)FindResource("IconKey"),
            Stroke = new SolidColorBrush(Color.FromRgb(0x6B, 0xA8, 0x6F)),
            StrokeThickness = 1.7,
            StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round,
        });
        iconCanvas.Children.Add(new Path
        {
            Data = (Geometry)FindResource("IconKeyDot"),
            Fill = new SolidColorBrush(Color.FromRgb(0x6B, 0xA8, 0x6F)),
        });
        var tile = new Border
        {
            Width = 34, Height = 34, CornerRadius = new CornerRadius(9), VerticalAlignment = VerticalAlignment.Center,
            Background = (Brush)FindResource("Surface"), BorderBrush = (Brush)FindResource("Border"), BorderThickness = new Thickness(1),
            Child = new Viewbox { Width = 16, Height = 16, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Child = iconCanvas },
        };
        Grid.SetColumn(tile, 0);

        // texts
        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var nameRow = new StackPanel { Orientation = Orientation.Horizontal };
        nameRow.Children.Add(new TextBlock
        {
            Text = key.Name, Foreground = (Brush)FindResource("TextBody"), FontSize = 13, FontWeight = FontWeights.SemiBold,
            TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center,
        });
        nameRow.Children.Add(new Border
        {
            Background = (Brush)FindResource("Surface"), BorderBrush = (Brush)FindResource("Border"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(5), Padding = new Thickness(6, 1, 6, 1), Margin = new Thickness(7, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = key.Type, FontFamily = (FontFamily)FindResource("MonoFont"), FontSize = 9.5,
                FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("TextSub"),
            },
        });
        texts.Children.Add(nameRow);
        texts.Children.Add(new TextBlock
        {
            Text = MidTruncate(key.Fingerprint, 40), FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 10, Foreground = (Brush)FindResource("TextHint"), Margin = new Thickness(0, 2, 0, 0),
            TextTrimming = TextTrimming.None,
        });
        texts.Children.Add(new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x0F, 0xFF, 0xFF, 0xFF)), CornerRadius = new CornerRadius(6),
            Padding = new Thickness(9, 3, 9, 3), Margin = new Thickness(0, 5, 0, 0), HorizontalAlignment = HorizontalAlignment.Left,
            Child = new TextBlock { Text = session.Cfg.Name, FontSize = 11, Foreground = (Brush)FindResource("TextSub") },
        });
        Grid.SetColumn(texts, 2);

        // actions: copy + toggle
        var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var copyCanvas = new Canvas { Width = 24, Height = 24 };
        copyCanvas.Children.Add(new Path
        {
            Data = (Geometry)FindResource("IconCopy"),
            StrokeThickness = 1.7, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
        });
        var copyPath = (Path)copyCanvas.Children[0];
        var copy = new Button { Style = (Style)FindResource("FlatIconButton"), ToolTip = Loc.T("ssh.copyPub") };
        copyPath.SetBinding(System.Windows.Shapes.Shape.StrokeProperty,
            new System.Windows.Data.Binding("Foreground") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(Button), 1) });
        copy.Content = new Viewbox { Width = 15, Height = 15, Child = copyCanvas };
        copy.Click += (_, __) =>
        {
            try { Clipboard.SetText(key.PublicKey); }
            catch { }
        };
        actions.Children.Add(copy);

        var toggle = new ToggleButton
        {
            Style = (Style)FindResource("ToggleSwitch"),
            IsChecked = !_cfg.SshDisabledKeys.Contains(key.Id),
            ToolTip = Loc.T("ssh.loadInAgent"),
            Margin = new Thickness(2, 0, 0, 0),
        };
        toggle.Checked += (_, __) => { _cfg.SshDisabledKeys.Remove(key.Id); RefreshStatus(); };
        toggle.Unchecked += (_, __) => { if (!_cfg.SshDisabledKeys.Contains(key.Id)) _cfg.SshDisabledKeys.Add(key.Id); RefreshStatus(); };
        actions.Children.Add(toggle);
        Grid.SetColumn(actions, 3);

        grid.Children.Add(tile);
        grid.Children.Add(texts);
        grid.Children.Add(actions);
        row.Child = grid;

        var wrap = new StackPanel { Margin = new Thickness(0, 0, 0, 4) };
        wrap.Children.Add(row);
        return wrap;
    }

    private void RefreshStatus()
    {
        int total = _keys.Count;
        int loaded = _keys.Count(k => !_cfg.SshDisabledKeys.Contains(k.Key.Id));
        HeaderStatus.Text = total == 0 ? Loc.T(_anyUnlocked ? "ssh.noKeysTitle" : "ssh.none")
            : total == 1 ? Loc.T("ssh.one") : Loc.T("ssh.many", total);
        LoadedText.Text = Loc.T("ssh.loadedStatus", loaded, total);
    }

    // "SHA256:abcdef...uvwxyz" mid-truncated like the design (max 40 chars, ellipsis in the middle)
    private static string MidTruncate(string s, int max)
    {
        if (s.Length <= max) return s;
        int head = (max - 1 + 1) / 2, tail = (max - 1) / 2;
        return s[..head] + "…" + s[^tail..];
    }

    private void Done_Click(object sender, RoutedEventArgs e)
    {
        _cfg.Save();
        DialogResult = true;
    }
}
