using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using VaultType.Config;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;
using Button = System.Windows.Controls.Button;
using Path = System.Windows.Shapes.Path;
using Orientation = System.Windows.Controls.Orientation;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Cursors = System.Windows.Input.Cursors;
using Control = System.Windows.Controls.Control;
using TextBox = System.Windows.Controls.TextBox;
using Shape = System.Windows.Shapes.Shape;

namespace VaultType.Views;

// A small read-only look into the vaults, meant for the offline copy: find an entry, reveal or copy
// a field. Nothing here can change the vault. Each vault gets its own section saying whether it is
// current, open from its offline copy (and from when), or locked - a locked one unlocks on click.
// Secrets stay protected until an explicit reveal or copy, revealed values hide again after a
// short while, and copies go through the clipboard auto-clear. App closes the window once every
// vault is locked.
public partial class VaultViewWindow : Window
{
    private static readonly TimeSpan RevealFor = TimeSpan.FromSeconds(30);
    private const string Masked = "••••••••";

    private readonly IReadOnlyList<VaultSession> _sessions;
    private readonly AppConfig _cfg;
    private readonly Func<VaultSession, bool> _verifyMasterPassword;
    private readonly Func<VaultSession, Task> _unlock;
    private List<(VaultSession Session, VaultItem Item)> _entries = new();
    private (VaultSession Session, string ItemId)? _open;

    // Entries whose master-password re-prompt was answered in this window; cleared when it closes.
    private readonly HashSet<string> _repromptPassed = new();
    private readonly List<DispatcherTimer> _hideTimers = new();

    public VaultViewWindow(IReadOnlyList<VaultSession> sessions, AppConfig cfg,
                           Func<VaultSession, bool> verifyMasterPassword, Func<VaultSession, Task> unlock)
    {
        InitializeComponent();
        _sessions = sessions;
        _cfg = cfg;
        _verifyMasterPassword = verifyMasterPassword;
        _unlock = unlock;

        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not TextBox) { try { DragMove(); } catch { } }
        };
        if (cfg.ExcludeFromScreenCapture)
            Loaded += (_, __) =>
                Native.SetWindowDisplayAffinity(new WindowInteropHelper(this).Handle, Native.WDA_EXCLUDEFROMCAPTURE);
        Loaded += (_, __) => { Activate(); SearchBox.Focus(); };
        Closed += (_, __) => StopHideTimers();

        Reload();
    }

    // Re-read the entries after a sync or a switch between offline copy and server. The items are
    // replaced on every sync and their secrets belong to the new protector, so stale references
    // must not be kept around.
    public void Reload()
    {
        _entries = _sessions.Where(s => s.Unlocked)
            .SelectMany(s => s.Items.Select(i => (s, i)))
            .OrderBy(e => e.i.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
        StatusText.Text = Loc.T("viewer.statusOnline");

        if (_open is { } open)
        {
            var still = _entries.FirstOrDefault(e => e.Session == open.Session && e.Item.Id == open.ItemId);
            if (still.Item != null) { ShowDetail(still.Session, still.Item); return; }
            _open = null;
        }
        ShowList();
    }

    // ---- list ----

    private void ShowList()
    {
        StopHideTimers();
        DetailScroll.Visibility = Visibility.Collapsed;
        SearchRow.Visibility = Visibility.Visible;
        ListScroll.Visibility = Visibility.Visible;

        string term = SearchBox.Text.Trim();
        EntryList.Children.Clear();
        int shown = 0;
        foreach (var session in _sessions)
        {
            var items = _entries.Where(e => e.Session == session && (term.Length == 0 || e.Item.Matches(term)))
                                .Select(e => e.Item).ToList();
            // While searching, an open vault without hits steps aside; a locked one stays visible
            // so it's clear its entries weren't searched.
            if (session.Unlocked && items.Count == 0 && term.Length > 0) continue;
            EntryList.Children.Add(SectionHeader(session, first: EntryList.Children.Count == 0));
            foreach (var item in items) EntryList.Children.Add(EntryRow(session, item));
            shown += items.Count;
        }

        EmptyText.Text = _entries.Count == 0 ? Loc.T("viewer.empty") : Loc.T("viewer.noMatch");
        EmptyText.Visibility = shown == 0 && _sessions.Any(s => s.Unlocked) ? Visibility.Visible : Visibility.Collapsed;
    }

    // Vault name in its colour, with where the entries below come from.
    private FrameworkElement SectionHeader(VaultSession session, bool first)
    {
        var grid = new Grid { Margin = new Thickness(10, first ? 2 : 14, 10, 4), Background = Brushes.Transparent };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        grid.Children.Add(new Border
        {
            Width = 9, Height = 9, CornerRadius = new CornerRadius(3), VerticalAlignment = VerticalAlignment.Center,
            Background = AvatarPalette.FromHex(session.Cfg.ColorHex),
        });
        var name = new TextBlock
        {
            Text = session.Cfg.Name, Foreground = (Brush)FindResource("TextBody"), FontSize = 12,
            FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(name, 2);
        grid.Children.Add(name);

        var state = new TextBlock
        {
            Text = SectionState(session), FontSize = 11, VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Foreground = (Brush)FindResource(session.Unlocked && session.Backend.IsOffline ? "Accent" : "TextHint"),
        };
        Grid.SetColumn(state, 4);
        grid.Children.Add(state);

        if (!session.Unlocked)
        {
            grid.Cursor = Cursors.Hand;
            grid.MouseLeftButtonUp += async (_, __) => await _unlock(session);
        }
        return grid;
    }

    private static string SectionState(VaultSession s)
    {
        if (!s.Unlocked) return Loc.T("viewer.sectionLocked");
        if (s.Backend.IsOffline)
            return Loc.T("viewer.sectionOffline", s.Backend.OfflineCopySavedUtc?.ToLocalTime().ToString("g") ?? "?");
        return s.Cfg.LastSyncUtc is { } synced
            ? Loc.T("viewer.sectionOnline", synced.ToLocalTime().ToString("g"))
            : Loc.T("viewer.sectionOnlineNow");
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_open == null) ShowList();
    }

    private FrameworkElement EntryRow(VaultSession session, VaultItem item)
    {
        var row = HoverRow();
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        grid.Children.Add(IconTile(KindIcon(item.Kind)));

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock
        {
            Text = item.Name, Foreground = (Brush)FindResource("TextBody"), FontSize = 13,
            FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis,
        });
        string sub = Subtitle(item);
        if (sub.Length > 0)
            texts.Children.Add(new TextBlock
            {
                Text = sub, Foreground = (Brush)FindResource("TextHint"), FontSize = 11.5,
                Margin = new Thickness(0, 1, 0, 0), TextTrimming = TextTrimming.CharacterEllipsis,
            });
        Grid.SetColumn(texts, 2);
        grid.Children.Add(texts);

        row.Child = grid;
        row.Cursor = Cursors.Hand;
        row.MouseLeftButtonUp += (_, __) => ShowDetail(session, item);
        return row;
    }

    private static string Subtitle(VaultItem item) => item.Kind switch
    {
        ItemKind.Card => string.Join(" ", new[] { item.Card?.Brand ?? "", item.Card?.Last4 is { Length: > 0 } l ? "•••• " + l : "" }
                                          .Where(p => p.Length > 0)),
        ItemKind.Identity => item.Identity?.FullName ?? "",
        _ => item.Username.Length > 0 ? item.Username : item.PrimaryHost,
    };

    private static string KindIcon(ItemKind kind) => kind switch
    {
        ItemKind.Card => "IconCard",
        ItemKind.Identity => "IconUser",
        _ => "IconKey",
    };

    // ---- detail ----

    private void ShowDetail(VaultSession session, VaultItem item)
    {
        StopHideTimers();
        _open = (session, item.Id);
        SearchRow.Visibility = Visibility.Collapsed;
        ListScroll.Visibility = Visibility.Collapsed;
        DetailScroll.Visibility = Visibility.Visible;
        DetailPanel.Children.Clear();

        var back = new Button { Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(6, 0, 0, 8) };
        var backContent = new StackPanel { Orientation = Orientation.Horizontal };
        backContent.Children.Add(Glyph("IconArrowLeft", 14));
        backContent.Children.Add(new TextBlock { Text = Loc.T("viewer.back"), Margin = new Thickness(6, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
        back.Content = backContent;
        back.Click += (_, __) => { _open = null; ShowList(); };
        DetailPanel.Children.Add(back);

        DetailPanel.Children.Add(new TextBlock
        {
            Text = item.Name, Foreground = Brushes.White, FontSize = 15, FontWeight = FontWeights.Bold,
            Margin = new Thickness(10, 0, 10, 10), TextWrapping = TextWrapping.Wrap,
        });

        var p = session.Protector;
        if (p == null) return;

        switch (item.Kind)
        {
            case ItemKind.Login:
                AddPlain(Loc.T("viewer.username"), item.Username);
                AddField(session, item, Loc.T("viewer.password"), ItemField.Password);
                AddField(session, item, Loc.T("viewer.totp"), ItemField.Totp);
                foreach (var u in item.Uris) AddPlain(Loc.T("viewer.website"), u.Value);
                break;
            case ItemKind.Card:
                AddPlain(Loc.T("viewer.cardholder"), item.Card?.CardholderName ?? "");
                AddField(session, item, Loc.T("viewer.cardNumber"), ItemField.CardNumber);
                AddField(session, item, Loc.T("viewer.cardExpiry"), ItemField.CardExpiry);
                AddField(session, item, Loc.T("viewer.cardCode"), ItemField.CardCode);
                break;
            case ItemKind.Identity:
                AddPlain(Loc.T("viewer.name"), item.Identity?.FullName ?? "");
                AddField(session, item, Loc.T("viewer.email"), ItemField.IdEmail);
                AddField(session, item, Loc.T("viewer.phone"), ItemField.IdPhone);
                AddField(session, item, Loc.T("viewer.address"), ItemField.IdAddress);
                break;
        }
        foreach (var f in item.CustomFields.Where(f => f.Value != null))
            AddSecret(session, item, f.Name, () => ClipboardService.SecretText(f.Value, p),
                      () => ClipboardService.CopySecret(f.Value, p, _cfg.ClipboardClearSeconds));
    }

    private void AddPlain(string label, string value)
    {
        if (value.Length == 0) return;
        DetailPanel.Children.Add(FieldRow(label, ValueText(value), CopyButton(() => ClipboardService.CopyText(value, _cfg.ClipboardClearSeconds))));
    }

    private void AddField(VaultSession session, VaultItem item, string label, ItemField field)
    {
        if (!item.Has(field)) return;
        var p = session.Protector!;
        AddSecret(session, item, label, () => ClipboardService.FieldText(item, field, p),
                  () => ClipboardService.Copy(item, field, p, _cfg.ClipboardClearSeconds));
    }

    // A protected field: masked until revealed, and the reveal hides itself again after RevealFor.
    private void AddSecret(VaultSession session, VaultItem item, string label, Func<string> reveal, Action copy)
    {
        var valueText = ValueText(Masked);
        bool shown = false;
        DispatcherTimer? hideTimer = null;
        var eye = IconButton("IconEye", Loc.T("viewer.reveal"));

        void Hide()
        {
            hideTimer?.Stop();
            valueText.Text = Masked;
            shown = false;
            SetGlyph(eye, "IconEye");
        }

        eye.Click += (_, __) =>
        {
            if (shown) { Hide(); return; }
            if (!Allowed(session, item)) return;
            string text;
            try { text = reveal(); }
            catch { Reload(); return; }   // the vault was re-synced underneath us
            if (text.Length == 0) return;
            valueText.Text = text;
            shown = true;
            SetGlyph(eye, "IconEyeOff");
            hideTimer ??= NewHideTimer(Hide);
            hideTimer.Stop();
            hideTimer.Start();
        };

        var copyBtn = CopyButton(() =>
        {
            if (!Allowed(session, item)) return;
            try { copy(); }
            catch { Reload(); }
        });
        DetailPanel.Children.Add(FieldRow(label, valueText, eye, copyBtn));
    }

    private DispatcherTimer NewHideTimer(Action hide)
    {
        var t = new DispatcherTimer { Interval = RevealFor };
        t.Tick += (_, __) => hide();
        _hideTimers.Add(t);
        return t;
    }

    private void StopHideTimers()
    {
        foreach (var t in _hideTimers) t.Stop();
        _hideTimers.Clear();
    }

    // Entries flagged "ask for the master password" in Bitwarden ask once per window.
    private bool Allowed(VaultSession session, VaultItem item)
    {
        if (!item.Reprompt || !_cfg.HonorMasterPasswordReprompt) return true;
        string key = session.Cfg.Id + "|" + item.Id;
        if (_repromptPassed.Contains(key)) return true;
        if (!_verifyMasterPassword(session)) return false;
        _repromptPassed.Add(key);
        return true;
    }

    // ---- building blocks ----

    private FrameworkElement FieldRow(string label, TextBlock value, params Button[] buttons)
    {
        var row = HoverRow();
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = label, Foreground = (Brush)FindResource("TextHint"), FontSize = 11 });
        texts.Children.Add(value);
        grid.Children.Add(texts);

        var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        foreach (var b in buttons) actions.Children.Add(b);
        Grid.SetColumn(actions, 1);
        grid.Children.Add(actions);

        row.Child = grid;
        return row;
    }

    private TextBlock ValueText(string text) => new()
    {
        Text = text, Foreground = (Brush)FindResource("TextBody"), FontSize = 13,
        FontFamily = (FontFamily)FindResource("MonoFont"), Margin = new Thickness(0, 2, 0, 0),
        TextWrapping = TextWrapping.Wrap,
    };

    private Button CopyButton(Action copy)
    {
        var b = IconButton("IconCopy", Loc.T("viewer.copy"));
        b.Click += (_, __) => copy();
        return b;
    }

    private Button IconButton(string icon, string tooltip) => new()
    {
        Style = (Style)FindResource("IconButton"), ToolTip = tooltip, Margin = new Thickness(2, 0, 0, 0),
        Content = Glyph(icon, 16),
    };

    private void SetGlyph(Button b, string icon) => b.Content = Glyph(icon, 16);

    private Border HoverRow()
    {
        var row = new Border { CornerRadius = new CornerRadius(9), Padding = new Thickness(10, 8, 8, 8), Background = Brushes.Transparent };
        row.MouseEnter += (_, __) => row.Background = (Brush)FindResource("Field");
        row.MouseLeave += (_, __) => row.Background = Brushes.Transparent;
        return row;
    }

    private Border IconTile(string icon) => new()
    {
        Width = 32, Height = 32, CornerRadius = new CornerRadius(8), Background = (Brush)FindResource("Field"),
        VerticalAlignment = VerticalAlignment.Center, Child = Glyph(icon, 16, (Brush)FindResource("TextSecondary")),
    };

    // Inside a button the icon follows the button's foreground (hover colour); elsewhere it gets
    // a fixed brush, since the nearest control up the tree would be the window itself.
    private Viewbox Glyph(string icon, double size, Brush? stroke = null)
    {
        var path = new Path
        {
            Data = (Geometry)FindResource(icon), StrokeThickness = 1.7,
            StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round,
        };
        if (stroke != null) path.Stroke = stroke;
        else
            path.SetBinding(Shape.StrokeProperty, new System.Windows.Data.Binding("Foreground")
            {
                RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(Control), 1),
            });
        var canvas = new Canvas { Width = 24, Height = 24 };
        canvas.Children.Add(path);
        return new Viewbox { Width = size, Height = size, Child = canvas, VerticalAlignment = VerticalAlignment.Center };
    }

    // Screenshot mode only: show the detail page of the first entry of the given kind.
    internal void OpenFirstEntry(ItemKind kind)
    {
        var e = _entries.FirstOrDefault(x => x.Item.Kind == kind);
        if (e.Item != null) ShowDetail(e.Session, e.Item);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            if (_open != null) { _open = null; ShowList(); }
            else Close();
            e.Handled = true;
        }
        base.OnKeyDown(e);
    }
}
