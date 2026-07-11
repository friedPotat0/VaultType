using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;

namespace VaultType.Views;

public enum PickAction { TypeFull, TypeUsername, TypePassword, TypeTotp, CopyUsername, CopyPassword, CopyTotp }

public sealed record PickResult(VaultItem Item, PickAction Action);

public partial class PickerWindow : Window
{
    private readonly IReadOnlyList<VaultItem> _all;
    private readonly IReadOnlyList<VaultItem> _matches;
    private readonly bool _excludeCapture;
    private readonly IconService _icons;
    private readonly bool _showAllFirst;
    private readonly Dictionary<VaultItem, ItemVM> _vmMap = new();

    public PickResult? Result { get; private set; }

    public PickerWindow(IReadOnlyList<VaultItem> all, IReadOnlyList<VaultItem> matches,
                        ForegroundInfo ctx, bool excludeCapture, IconService icons, bool showAllFirst = false)
    {
        InitializeComponent();
        _all = all;
        _matches = matches;
        _excludeCapture = excludeCapture;
        _icons = icons;
        _showAllFirst = showAllFirst;

        ContextLabel.Text = Loc.T("picker.for") + " " + (string.IsNullOrEmpty(ctx.Url)
            ? (string.IsNullOrEmpty(ctx.Exe) ? ctx.Title : ctx.Exe)
            : Matcher.HostDomain(ctx.Url!).host);

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Search.GotKeyboardFocus += (_, __) => SearchBorder.BorderBrush = (Brush)FindResource("Accent");
        Search.LostKeyboardFocus += (_, __) => SearchBorder.BorderBrush = (Brush)FindResource("Border");
        Loaded += OnLoaded;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        ShowDefault();
        Activate();
        Search.Focus();
    }

    private ItemVM Vm(VaultItem it)
    {
        if (!_vmMap.TryGetValue(it, out var vm)) { vm = new ItemVM(it); _vmMap[it] = vm; }
        return vm;
    }

    private void ShowDefault()
    {
        if (!_showAllFirst && _matches.Count > 0) SetList(_matches, Loc.T("picker.matching", _matches.Count));
        else SetList(_all, Loc.T("picker.all", _all.Count));
    }

    private void SetList(IReadOnlyList<VaultItem> items, string section)
    {
        var vms = items.Select(Vm).ToList();
        List.ItemsSource = vms;
        SectionLabel.Text = section;
        if (vms.Count > 0) List.SelectedIndex = 0;
        foreach (var vm in vms) LoadIcon(vm);
    }

    private async void LoadIcon(ItemVM vm)
    {
        if (vm.Icon != null) return;
        try { var img = await _icons.GetAsync(vm.IconDomain); if (img != null) vm.Icon = img; }
        catch { }
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        string term = Search.Text.Trim();
        bool empty = string.IsNullOrEmpty(Search.Text);
        Placeholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        ClearBtn.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;

        if (term.Length == 0) { ShowDefault(); return; }

        var filtered = _all.Where(it => it.Matches(term)).ToList();
        SetList(filtered, Loc.T("picker.results", filtered.Count));
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        switch (e.Key)
        {
            case Key.Down: MoveSelection(+1); e.Handled = true; break;
            case Key.Up: MoveSelection(-1); e.Handled = true; break;
            case Key.Enter: Choose(PickAction.TypeFull); e.Handled = true; break;
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
        if ((action == PickAction.TypeTotp || action == PickAction.CopyTotp) && !item.HasTotp) return;
        Result = new PickResult(item, action);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        Search.Clear();
        Search.Focus();
    }
}
