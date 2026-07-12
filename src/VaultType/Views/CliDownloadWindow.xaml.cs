using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Views;

// Proper download dialog for the CLI: progress bar, transferred/total size, speed and ETA.
public partial class CliDownloadWindow : Window
{
    private readonly bool _excludeCapture;
    private readonly Stopwatch _sw = Stopwatch.StartNew();
    private long _lastBytes;
    private double _lastSampleAt;
    private double _speed;   // bytes/sec, smoothed so the number doesn't jump around

    public event Action? Cancelled;

    public CliDownloadWindow(bool excludeCapture, string source)
    {
        InitializeComponent();
        _excludeCapture = excludeCapture;
        SourceText.Text = Loc.T("cli.dlSource", source);

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
    }

    public void Report(long read, long? total)
    {
        double now = _sw.Elapsed.TotalSeconds;
        double dt = now - _lastSampleAt;
        if (dt >= 0.3)
        {
            double inst = (read - _lastBytes) / dt;
            _speed = _speed <= 0 ? inst : 0.65 * _speed + 0.35 * inst;
            _lastBytes = read;
            _lastSampleAt = now;
        }
        Render(read, total, _speed);
    }

    // Used by the screenshot mode to render a representative mid-download frame.
    public void Preview(long read, long total, double bytesPerSecond) => Render(read, total, bytesPerSecond);

    private void Render(long read, long? total, double speed)
    {
        bool done = total is > 0 && read >= total.Value;
        if (total is > 0)
        {
            Bar.Value = read * 100.0 / total.Value;
            Percent.Text = (int)(read * 100 / total.Value) + "%";
            SizeText.Text = $"{Human(read)} / {Human(total.Value)}";
        }
        else SizeText.Text = Human(read);

        string sp = speed > 0 ? $"{Human((long)speed)}/s" : "";
        string eta = total is > 0 && speed > 0 && !done
            ? Loc.T("cli.dlEta", Duration((total.Value - read) / speed))
            : "";
        RateText.Text = string.Join("   ·   ", new[] { sp, eta }.Where(x => x.Length > 0));
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Cancelled?.Invoke();

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) Cancelled?.Invoke();
        base.OnKeyDown(e);
    }

    private static string Human(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        int i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return b.ToString(i == 0 ? "0" : "0.0", CultureInfo.InvariantCulture) + " " + units[i];
    }

    private static string Duration(double seconds)
    {
        int s = (int)Math.Ceiling(seconds);
        return s < 60 ? s + "s" : s / 60 + "m " + s % 60 + "s";
    }
}
