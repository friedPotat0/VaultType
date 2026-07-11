using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Views;

public partial class ConfirmWindow : Window
{
    private readonly bool _excludeCapture;

    public ConfirmWindow(string heading, string message, bool excludeCapture)
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        Heading.Text = heading;
        Message.Text = message;

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

    private void Yes_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void No_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) DialogResult = false;
        base.OnKeyDown(e);
    }
}
