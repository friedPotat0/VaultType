using System.Windows;
using CheckBox = System.Windows.Controls.CheckBox;
using TextBlock = System.Windows.Controls.TextBlock;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Views;

public partial class ConfirmWindow : Window
{
    private readonly bool _excludeCapture;

    // `confirmText` overrides the "Yes" label; `showCancel: false` turns the dialog into a plain
    // notice with a single button to dismiss it. `options` adds unchecked check boxes below the
    // message, at most one of which can be ticked; read SelectedOption after a confirmed ShowDialog.
    public ConfirmWindow(string heading, string message, bool excludeCapture,
                         string? confirmText = null, bool showCancel = true, IReadOnlyList<string>? options = null)
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        Heading.Text = heading;
        Message.Text = message;
        if (confirmText != null) YesBtn.Content = confirmText;
        // Collapsing leaves the confirm button in its own column, so the layout stays put.
        if (!showCancel) NoBtn.Visibility = Visibility.Collapsed;
        if (options is { Count: > 0 })
        {
            foreach (string text in options)
            {
                var box = new CheckBox
                {
                    Margin = new Thickness(0, 10, 0, 0),
                    Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, MaxWidth = 300 },
                };
                // Ticking one option clears the others: they are alternatives, not additions.
                box.Checked += (_, _) =>
                {
                    foreach (var other in _options)
                        if (!ReferenceEquals(other, box)) other.IsChecked = false;
                };
                _options.Add(box);
                OptionsPanel.Children.Add(box);
            }
            OptionsPanel.Visibility = Visibility.Visible;
        }

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        Activate();
        YesBtn.Focus();
    }

    private readonly List<CheckBox> _options = new();

    // Index of the ticked option, or -1 when none is ticked.
    public int SelectedOption => _options.FindIndex(b => b.IsChecked == true);

    private void Yes_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void No_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) DialogResult = false;
        base.OnKeyDown(e);
    }
}
