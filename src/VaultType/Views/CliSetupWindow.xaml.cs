using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;
using DragEventArgs = System.Windows.DragEventArgs;         // disambiguate from the WinForms types
using DragDropEffects = System.Windows.DragDropEffects;
using DataFormats = System.Windows.DataFormats;

namespace VaultType.Views;

public enum CliSetupChoice { Cancel, Download, Manual }

// First-run consent: let the user decide whether VaultType downloads the official Bitwarden CLI
// or whether they add it themselves. Nothing touches the network until they pick. The manual path
// deliberately avoids the Windows file dialog - that loads shell extensions into the process, and a
// broken third-party one (WinFsp, NVIDIA overlay, ...) can crash it. Drag-and-drop instead.
public partial class CliSetupWindow : Window
{
    private readonly bool _excludeCapture;
    private readonly string _targetPath;
    private FileSystemWatcher? _watcher;

    public CliSetupChoice Choice { get; private set; } = CliSetupChoice.Cancel;
    public string? SelectedFile { get; private set; }   // a dragged file to copy; null once it's already at the target

    public CliSetupWindow(bool excludeCapture, string targetPath, string downloadUrl)
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        _targetPath = targetPath;
        SourceHint.Text = Loc.T("cli.downloadHint", downloadUrl);
        ManualHint.Text = Loc.T("cli.selectHint");

        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) { try { DragMove(); } catch { } } };
        Loaded += OnLoaded;
        Closed += (_, __) => { _watcher?.Dispose(); _watcher = null; };
    }

    private void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (_excludeCapture)
        {
            var h = new WindowInteropHelper(this).Handle;
            Native.SetWindowDisplayAffinity(h, Native.WDA_EXCLUDEFROMCAPTURE);
        }
        Activate();
    }

    private void Download_Click(object sender, RoutedEventArgs e)
    {
        Choice = CliSetupChoice.Download;
        DialogResult = true;
    }

    // Open the destination folder and watch it, so dropping bw.exe in there finishes setup.
    private void Select_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string dir = Path.GetDirectoryName(_targetPath)!;
            Directory.CreateDirectory(dir);
            StartWatching(dir);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
            ManualHint.Text = Loc.T("cli.waiting", dir);
        }
        catch { }
    }

    private void StartWatching(string dir)
    {
        if (_watcher != null) return;
        _watcher = new FileSystemWatcher(dir, "bw.exe") { EnableRaisingEvents = true };
        void OnChange(object _, FileSystemEventArgs __) => Dispatcher.BeginInvoke(CompleteIfPresent);
        _watcher.Created += OnChange;
        _watcher.Changed += OnChange;
        _watcher.Renamed += (_, __) => Dispatcher.BeginInvoke(CompleteIfPresent);
    }

    private void CompleteIfPresent()
    {
        if (!File.Exists(_targetPath)) return;
        SelectedFile = null;   // already at the target - the caller doesn't need to copy anything
        Choice = CliSetupChoice.Manual;
        try { DialogResult = true; } catch { }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = ExeFrom(e) != null ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        string? file = ExeFrom(e);
        if (file == null) return;
        SelectedFile = file;
        Choice = CliSetupChoice.Manual;
        DialogResult = true;
    }

    private static string? ExeFrom(DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return null;
        var files = e.Data.GetData(DataFormats.FileDrop) as string[];
        return files?.FirstOrDefault(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) DialogResult = false;
        base.OnKeyDown(e);
    }
}
