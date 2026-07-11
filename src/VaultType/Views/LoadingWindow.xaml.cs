using System.Windows;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Views;

public partial class LoadingWindow : Window
{
    private readonly bool _excludeCapture;

    public LoadingWindow(bool excludeCapture)
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        Loaded += OnLoaded;
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
    }

    public void SetStatus(string text) => StatusText.Text = text;
}
