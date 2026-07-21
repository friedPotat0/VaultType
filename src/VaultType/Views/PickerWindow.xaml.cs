using System.Linq;
using System.Windows;
using System.Windows.Controls;
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

public enum PickAction { TypeFull, TypeUsername, TypePassword, TypeTotp, CopyUsername, CopyPassword, CopyTotp }

public sealed record PickResult(VaultItem Item, PickAction Action, VaultSession Session);

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

    private void ShowDefault()
    {
        if (!_showAllFirst && _matches.Count > 0) SetList(_matches, Loc.T("picker.matching", _matches.Count));
        else if (_all.Count > 0) SetList(_all, _hostLabel.Length > 0 ? Loc.T("picker.allFor", _hostLabel) : Loc.T("picker.all", _all.Count));
        else SetList(_all, HasLocked ? Loc.T("picker.unlockPrompt") : Loc.T("picker.all", 0));
    }

    // After an in-place unlock, keep whatever the user was looking at.
    private void ReapplyView()
    {
        string term = Search.Text.Trim();
        if (term.Length == 0) ShowDefault();
        else Search_TextChanged(Search, null!);
    }

    private void SetList(IReadOnlyList<(VaultItem it, VaultSession s)> items, string section)
    {
        var vms = items.Select(x => Vm(x.it, x.s)).ToList();
        List.ItemsSource = vms;
        SectionLabel.Text = section;

        bool hasItems = vms.Count > 0;
        List.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
        EmptyPanel.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        if (!hasItems) ShowEmptyState();

        if (hasItems) List.SelectedIndex = 0;
        foreach (var vm in vms) LoadIcon(vm);
    }

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
            var s = _sessions.FirstOrDefault(x => !x.Unlocked);
            LockedTitle.Text = Loc.T("picker.lockedTitle", s?.Cfg.Name ?? "");
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
        if (vm.Icon != null) return;
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

        var filtered = _all.Where(x => x.it.Matches(term)).ToList();
        SetList(filtered, Loc.T("picker.results", filtered.Count));
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
                else Choose(PickAction.TypeFull);
                e.Handled = true; break;
            case Key.Escape: DialogResult = false; e.Handled = true; break;
            case Key.U when ctrl: Choose(PickAction.TypeUsername); e.Handled = true; break;
            case Key.P when ctrl: Choose(PickAction.TypePassword); e.Handled = true; break;
            case Key.T when ctrl: Choose(PickAction.TypeTotp); e.Handled = true; break;
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

    private void List_DoubleClick(object sender, MouseButtonEventArgs e) => Choose(PickAction.TypeFull);

    private void List_RightDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? d = e.OriginalSource as DependencyObject;
        while (d != null && d is not ListBoxItem) d = VisualTreeHelper.GetParent(d);
        if (d is ListBoxItem lbi) lbi.IsSelected = true;
    }

    // Only offer copy actions for fields the entry actually has.
    private void List_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (List.SelectedItem is not ItemVM vm || List.ContextMenu is null) { e.Handled = true; return; }
        var item = vm.Item;
        var items = List.ContextMenu.Items;
        ((MenuItem)items[0]).Visibility = string.IsNullOrEmpty(item.Username) ? Visibility.Collapsed : Visibility.Visible;
        ((MenuItem)items[1]).Visibility = item.Password == null ? Visibility.Collapsed : Visibility.Visible;
        ((MenuItem)items[2]).Visibility = item.HasTotp ? Visibility.Visible : Visibility.Collapsed;
        if (string.IsNullOrEmpty(item.Username) && item.Password == null && !item.HasTotp)
            e.Handled = true; // nothing to copy -> don't open the menu
    }

    private void CopyUser_Click(object sender, RoutedEventArgs e) => Choose(PickAction.CopyUsername);
    private void CopyPass_Click(object sender, RoutedEventArgs e) => Choose(PickAction.CopyPassword);
    private void CopyTotp_Click(object sender, RoutedEventArgs e) => Choose(PickAction.CopyTotp);

    private void Choose(PickAction action)
    {
        if (List.SelectedItem is not ItemVM vm) return;
        var item = vm.Item;
        // Guard the keyboard shortcuts (Ctrl+U/P/T) for absent fields exactly like the context menu
        // hides them - otherwise an entry with no password would still fire a TypePassword action.
        if ((action is PickAction.TypeTotp or PickAction.CopyTotp) && !item.HasTotp) return;
        if ((action is PickAction.TypeUsername or PickAction.CopyUsername) && string.IsNullOrEmpty(item.Username)) return;
        if ((action is PickAction.TypePassword or PickAction.CopyPassword) && item.Password == null) return;
        Result = new PickResult(item, action, vm.Session);
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

    private void BuildChips()
    {
        LockedBar.Children.Clear();
        var locked = _sessions.Where(s => !s.Unlocked).ToList();
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
        var s = _sessions.FirstOrDefault(x => !x.Unlocked);
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
