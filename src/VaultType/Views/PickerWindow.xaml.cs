using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;
// WinForms is in scope (UseWindowsForms), so pin these names to their WPF types.
using Button = System.Windows.Controls.Button;
using Orientation = System.Windows.Controls.Orientation;
using Cursors = System.Windows.Input.Cursors;
using ColorConverter = System.Windows.Media.ColorConverter;   // vs System.Drawing.ColorConverter

namespace VaultType.Views;

public enum PickAction { Type, Copy }

// What the user picked: an entry, whether to type or copy, and which field. ItemField.None with
// PickAction.Type means the whole entry, i.e. its custom or default sequence.
public sealed record PickResult(VaultItem Item, PickAction Action, ItemField Field, VaultSession Session);

public partial class PickerWindow : Window
{
    private readonly IReadOnlyList<VaultSession> _sessions;
    private readonly ForegroundInfo _ctx;
    private readonly int _defaultMatch;
    private readonly bool _excludeCapture;
    private readonly bool _showAllFirst;
    private readonly bool _showBadges;
    private readonly Func<VaultSession, Task<bool>> _unlockAsync;
    private readonly Dictionary<VaultItem, ItemVM> _vmMap = new();

    // aggregated across every unlocked session; each entry keeps its owning session
    private List<(VaultItem it, VaultSession s)> _all = new();
    private List<(VaultItem it, VaultSession s)> _matches = new();
    private bool _unlocking;
    private string _hostLabel = "";   // the foreground host, shown on the section label

    public PickResult? Result { get; private set; }

    // entries that matched the foreground context, for the "remember this entry?" offer
    public IReadOnlyList<VaultItem> Matches => _matches.Select(x => x.it).ToList();

    public PickerWindow(IReadOnlyList<VaultSession> sessions, ForegroundInfo ctx, int defaultMatch,
                        bool excludeCapture, bool showAllFirst, Func<VaultSession, Task<bool>> unlockAsync)
    {
        InitializeComponent();
        _sessions = sessions;
        _ctx = ctx;
        _defaultMatch = defaultMatch;
        _excludeCapture = excludeCapture;
        _showAllFirst = showAllFirst;
        _unlockAsync = unlockAsync;
        _showBadges = sessions.Count > 1;

        // Header subtitle: static hint (matches the design). The context host is shown on the section label.
        ContextLabel.Text = Loc.T("picker.hint");
        _hostLabel = string.IsNullOrEmpty(ctx.Url)
            ? (string.IsNullOrEmpty(ctx.Exe) ? ctx.Title : ctx.Exe)
            : Matcher.HostDomain(ctx.Url!).host;

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        // design focus state: brighter fill + stronger border (not green)
        Search.GotKeyboardFocus += (_, __) => { SearchBorder.Background = (Brush)FindResource("Surface"); SearchBorder.BorderBrush = (Brush)FindResource("BorderStrong"); };
        Search.LostKeyboardFocus += (_, __) => { SearchBorder.Background = (Brush)FindResource("Field"); SearchBorder.BorderBrush = (Brush)FindResource("Border"); };
        Loaded += OnLoaded;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        Rebuild();
        BuildChips();
        ShowDefault();
        Activate();
        Search.Focus();
    }

    // Recompute the aggregated item/match lists from every unlocked session.
    private void Rebuild()
    {
        _all = new();
        _matches = new();
        foreach (var s in _sessions)
        {
            if (!s.Unlocked) continue;
            foreach (var it in s.Items) _all.Add((it, s));
            foreach (var it in Matcher.FindMatches(s.Items, _ctx, _defaultMatch)) _matches.Add((it, s));
        }
    }

    private ItemVM Vm(VaultItem it, VaultSession s)
    {
        if (!_vmMap.TryGetValue(it, out var vm)) { vm = new ItemVM(it, s, _showBadges); _vmMap[it] = vm; }
        return vm;
    }

    // Logins only appear when they match the active window, or when the tray opened the picker,
    // where there is no context to match against. Identities and cards follow regardless: unlike a
    // login they aren't tied to a domain, so they can be wanted on any page.
    private void ShowDefault()
    {
        var rows = new List<Row>();
        string? hint = null;
        var logins = Logins(_all);

        if (_showAllFirst)
            AddRows(rows, logins, Loc.T("picker.all", logins.Count));
        else if (_matches.Count > 0)
            AddRows(rows, _matches, Loc.T("picker.matching", _matches.Count));
        else if (logins.Count > 0)
            hint = _hostLabel.Length > 0 ? Loc.T("picker.noMatchFor", _hostLabel) : Loc.T("picker.noMatchApp");

        AppendExtras(rows, _all);
        SetList(rows, hint);
    }

    // Identities and cards, in that order, appended below whatever the logins section holds.
    private void AppendExtras(List<Row> rows, IReadOnlyList<(VaultItem it, VaultSession s)> source)
    {
        var ids = source.Where(x => x.it.Kind == ItemKind.Identity).ToList();
        var cards = source.Where(x => x.it.Kind == ItemKind.Card).ToList();
        AddRows(rows, ids, Loc.T("picker.groupIdentities", ids.Count));
        AddRows(rows, cards, Loc.T("picker.groupCards", cards.Count));
    }

    private static List<(VaultItem it, VaultSession s)> Logins(IReadOnlyList<(VaultItem it, VaultSession s)> source)
        => source.Where(x => x.it.Kind == ItemKind.Login).ToList();

    private void AddRows(List<Row> rows, IReadOnlyList<(VaultItem it, VaultSession s)> items, string group)
    {
        foreach (var x in items) rows.Add(new Row(x.it, x.s, group));
    }

    // After an in-place unlock, keep whatever the user was looking at.
    private void ReapplyView()
    {
        string term = Search.Text.Trim();
        if (term.Length == 0) ShowDefault();
        else Search_TextChanged(Search, null!);
    }

    private void SetList(IReadOnlyList<Row> rows, string? hint)
    {
        var vms = rows.Select(r => { var vm = Vm(r.Item, r.Session); vm.GroupLabel = r.Group; return vm; }).ToList();

        // Group headers come from GroupLabel; the source order decides the order of the blocks.
        var view = new CollectionViewSource { Source = vms };
        view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ItemVM.GroupLabel)));
        List.ItemsSource = view.View;

        bool hasItems = vms.Count > 0;
        bool showHint = hasItems && !string.IsNullOrEmpty(hint);

        // The hint sits above the sections. With nothing to show at all the empty state already
        // explains the situation, so showing both would say the same thing twice.
        HintLabel.Text = hint ?? "";
        HintBox.Visibility = showHint ? Visibility.Visible : Visibility.Collapsed;

        List.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
        EmptyPanel.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        if (!hasItems) ShowEmptyState();

        // Only preselect when the first row is actually a suggestion. Without a matching login the
        // list starts at the identities, and highlighting one would present it as the match the
        // hint just said doesn't exist - Enter would then type the wrong entry.
        List.SelectedIndex = hasItems && !showHint ? 0 : -1;
        foreach (var vm in vms) LoadIcon(vm);
    }

    private readonly record struct Row(VaultItem Item, VaultSession Session, string Group);

    // No rows: either every vault is locked (show the unlock hint) or the unlocked vaults hold
    // nothing for this context (show the empty hint), matching the design's two in-list states.
    private void ShowEmptyState()
    {
        bool anyUnlocked = _sessions.Any(s => s.Unlocked);
        bool searching = Search.Text.Trim().Length > 0;
        string label = _hostLabel.Length > 0 ? _hostLabel : (_ctx.Exe.Length > 0 ? _ctx.Exe : _ctx.Title);

        LockedState.Visibility = (!anyUnlocked && !searching) ? Visibility.Visible : Visibility.Collapsed;
        NoEntriesState.Visibility = (anyUnlocked || searching) ? Visibility.Visible : Visibility.Collapsed;

        if (!anyUnlocked && !searching)
        {
            LockedTitle.Text = Loc.T("picker.lockedTitle", PreferredLocked()?.Cfg.Name ?? "");
        }
        else
        {
            EmptyTitle.Text = searching
                ? Loc.T("picker.results", 0)
                : Loc.T("picker.emptyTitle", _sessions.FirstOrDefault(x => x.Unlocked)?.Cfg.Name ?? "");
            EmptyMsg.Text = _hostLabel.Length > 0 ? Loc.T("picker.emptyMsg", label) : Loc.T("picker.emptyMsgApp");
        }
    }

    private async void LoadIcon(ItemVM vm)
    {
        if (!vm.WantsFavicon || vm.Icon != null) return;   // cards and identities have no website
        try { var img = await vm.Session.Icons.GetAsync(vm.IconDomain); if (img != null) vm.Icon = img; }
        catch { }
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        string term = Search.Text.Trim();
        bool empty = string.IsNullOrEmpty(Search.Text);
        Placeholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        ClearBtn.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;

        if (term.Length == 0) { ShowDefault(); return; }

        // A search reaches across everything, but keeps the same grouping so the kind of entry
        // stays obvious.
        var hits = _all.Where(x => x.it.Matches(term)).ToList();
        var rows = new List<Row>();
        var logins = Logins(hits);
        AddRows(rows, logins, Loc.T("picker.groupLogins", logins.Count));
        AppendExtras(rows, hits);
        SetList(rows, null);
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        switch (e.Key)
        {
            case Key.Down: MoveSelection(+1); e.Handled = true; break;
            case Key.Up: MoveSelection(-1); e.Handled = true; break;
            case Key.Enter:
                // Nothing to type yet but a locked account waiting -> unlock it (keyboard path).
                if (List.SelectedItem is not ItemVM && HasLocked) UnlockFirstLocked();
                else Choose(PickAction.Type, ItemField.None);
                e.Handled = true; break;
            case Key.Escape: DialogResult = false; e.Handled = true; break;
            // The single-field shortcuts stay login-only; cards and identities have far too many
            // fields to bind sensibly and are served through the context menu instead.
            case Key.U when ctrl: Choose(PickAction.Type, ItemField.Username); e.Handled = true; break;
            case Key.P when ctrl: Choose(PickAction.Type, ItemField.Password); e.Handled = true; break;
            case Key.T when ctrl: Choose(PickAction.Type, ItemField.Totp); e.Handled = true; break;
        }
        base.OnPreviewKeyDown(e);
    }

    private void MoveSelection(int delta)
    {
        int count = List.Items.Count;
        if (count == 0) return;
        int i = List.SelectedIndex + delta;
        if (i < 0) i = 0;
        if (i >= count) i = count - 1;
        List.SelectedIndex = i;
        List.ScrollIntoView(List.SelectedItem);
    }

    private void List_DoubleClick(object sender, MouseButtonEventArgs e) => Choose(PickAction.Type, ItemField.None);

    private void List_RightDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? d = e.OriginalSource as DependencyObject;
        while (d != null && d is not ListBoxItem) d = VisualTreeHelper.GetParent(d);
        if (d is ListBoxItem lbi) lbi.IsSelected = true;
    }

    // The per-field menu differs by entry type; fields the entry doesn't carry are left out.
    private static readonly (ItemField Field, string Key)[] LoginFields =
    {
        (ItemField.Username, "field.username"), (ItemField.Password, "field.password"), (ItemField.Totp, "field.totp"),
    };
    private static readonly (ItemField Field, string Key)[] CardFields =
    {
        (ItemField.CardNumber, "field.cardNumber"), (ItemField.CardExpiry, "field.cardExpiry"),
        (ItemField.CardCode, "field.cardCode"), (ItemField.CardHolder, "field.cardHolder"),
    };
    private static readonly (ItemField Field, string Key)[] IdentityFields =
    {
        (ItemField.IdName, "field.idName"), (ItemField.IdEmail, "field.idEmail"),
        (ItemField.IdPhone, "field.idPhone"), (ItemField.IdAddress, "field.idAddress"),
    };

    private static (ItemField Field, string Key)[] FieldsFor(VaultItem item) => item.Kind switch
    {
        ItemKind.Card => CardFields,
        ItemKind.Identity => IdentityFields,
        _ => LoginFields,
    };

    // Rebuild the menu for the selected entry: a "type" block, a separator, then a "copy" block.
    private void List_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (List.SelectedItem is not ItemVM vm || List.ContextMenu is null) { e.Handled = true; return; }
        var item = vm.Item;
        var present = FieldsFor(item).Where(f => item.Has(f.Field)).ToList();
        if (present.Count == 0) { e.Handled = true; return; }   // nothing to offer -> don't open

        var menu = List.ContextMenu;
        menu.Items.Clear();

        foreach (var (field, key) in present)
            menu.Items.Add(MakeFieldItem(Loc.T("picker.typeField", Loc.T(key)), PickAction.Type, field,
                                         field == ItemField.Username ? "⌃U"
                                       : field == ItemField.Password ? "⌃P"
                                       : field == ItemField.Totp ? "⌃T" : ""));

        menu.Items.Add(new Separator());

        foreach (var (field, key) in present)
            menu.Items.Add(MakeFieldItem(Loc.T("picker.copyField", Loc.T(key)), PickAction.Copy, field, ""));
    }

    private MenuItem MakeFieldItem(string header, PickAction action, ItemField field, string gesture)
    {
        var mi = new MenuItem { Header = header, InputGestureText = gesture };
        mi.Click += (_, __) => Choose(action, field);
        return mi;
    }

    private void Choose(PickAction action, ItemField field)
    {
        if (List.SelectedItem is not ItemVM vm) return;
        var item = vm.Item;
        // Guard the keyboard shortcuts for absent fields exactly like the context menu leaves them
        // out - otherwise an entry with no password would still fire a password action.
        if (!item.Has(field)) return;
        Result = new PickResult(item, action, field, vm.Session);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        Search.Clear();
        Search.Focus();
    }

    // ---- locked-account footer (unlock more vaults without leaving the picker) ----

    private bool HasLocked => _sessions.Any(s => !s.Unlocked);

    // The vault unlocked most recently is almost always the one wanted again; list order would
    // keep offering the same one regardless of what the user actually works with.
    private VaultSession? PreferredLocked()
        => _sessions.Where(s => !s.Unlocked)
                    .OrderByDescending(s => s.Cfg.LastUnlockedUtc ?? DateTimeOffset.MinValue)
                    .FirstOrDefault();

    private void BuildChips()
    {
        LockedBar.Children.Clear();
        var locked = _sessions.Where(s => !s.Unlocked)
                              .OrderByDescending(s => s.Cfg.LastUnlockedUtc ?? DateTimeOffset.MinValue)
                              .ToList();
        LockedBar.Visibility = locked.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var s in locked) LockedBar.Children.Add(MakeChip(s));
    }

    private Button MakeChip(VaultSession s)
    {
        var grey = (Brush)FindResource("TextMuted");
        var icon = new Viewbox
        {
            Width = 11, Height = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0),
            Child = new Canvas
            {
                Width = 24, Height = 24,
                Children = { new System.Windows.Shapes.Path
                {
                    Data = (System.Windows.Media.Geometry)FindResource("IconLock"),
                    Stroke = grey, StrokeThickness = 2,
                    StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
                } },
            },
        };
        var name = new TextBlock
        {
            Text = s.Cfg.Name.Length > 0 ? s.Cfg.Name : s.Cfg.DeriveName(),
            Foreground = grey, FontSize = 11.5, VerticalAlignment = VerticalAlignment.Center,
        };
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(icon);
        sp.Children.Add(name);
        var btn = new Button
        {
            Content = sp, Tag = s, Cursor = Cursors.Hand, Margin = new Thickness(16, 0, 0, 0),
            Style = (Style)FindResource("IndicatorButton"),
            ToolTip = Loc.T("picker.unlockChipHint"),
        };
        // design: the whole indicator brightens to white on hover
        var white = new SolidColorBrush(Colors.White);
        btn.MouseEnter += (_, __) => { ((System.Windows.Shapes.Path)((Canvas)icon.Child).Children[0]).Stroke = white; name.Foreground = white; };
        btn.MouseLeave += (_, __) => { ((System.Windows.Shapes.Path)((Canvas)icon.Child).Children[0]).Stroke = grey; name.Foreground = grey; };
        btn.Click += Chip_Click;
        return btn;
    }

    private void UnlockFirstLocked()
    {
        var s = PreferredLocked();
        if (s != null) _ = UnlockSession(s);
    }

    private async void Chip_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.Tag is VaultSession s) await UnlockSession(s);
    }

    private async Task UnlockSession(VaultSession s)
    {
        if (_unlocking) return;
        _unlocking = true;
        try
        {
            bool ok = await _unlockAsync(s);
            if (ok) { Rebuild(); BuildChips(); ReapplyView(); }
        }
        catch { /* unlock failure already surfaced by the caller */ }
        finally { _unlocking = false; }
        Activate();
        Search.Focus();
    }
}
