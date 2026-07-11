using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Config;
using VaultType.Security;
using VaultType.Services;

namespace VaultType.Views;

public partial class SettingsWindow : Window
{
    private readonly AppConfig _cfg;
    private readonly bool _excludeCapture;
    private readonly string[] _langCodes;

    public SettingsWindow(AppConfig cfg, bool excludeCapture)
    {
        InitializeComponent();
        _cfg = cfg;
        _excludeCapture = excludeCapture;

        ServerBox.Text = cfg.ServerUrl;
        HotkeyBox.Text = cfg.Hotkey;
        IdleBox.Text = cfg.IdleTimeoutMinutes.ToString();
        ClipBox.Text = cfg.ClipboardClearSeconds.ToString();
        DelayBox.Text = cfg.TypingDelayMs.ToString();
        ClearFieldChk.IsChecked = cfg.ClearFieldBeforeTyping;
        AutostartChk.IsChecked = cfg.Autostart;
        TrayClickChk.IsChecked = cfg.EnableTrayClick;
        ExcludeCapChk.IsChecked = cfg.ExcludeFromScreenCapture;
        AntiDbgChk.IsChecked = cfg.AntiDebugger;

        _langCodes = new string[Loc.Languages.Length + 1];
        _langCodes[0] = "auto";
        LangBox.Items.Add(Loc.T("settings.langAuto"));
        for (int i = 0; i < Loc.Languages.Length; i++)
        {
            _langCodes[i + 1] = Loc.Languages[i].Code;
            LangBox.Items.Add(Loc.Languages[i].Name);
        }
        int li = Array.FindIndex(_langCodes, c => c.Equals(cfg.Language, StringComparison.OrdinalIgnoreCase));
        LangBox.SelectedIndex = li < 0 ? 0 : li;

        VersionRun.Text = "v" + AppInfo.Version;

        HotkeyBox.PreviewKeyDown += HotkeyBox_PreviewKeyDown;
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
    }

    // Capture a key combination directly instead of typing it.
    private void HotkeyBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        e.Handled = true;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;

        if (key is Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt
            or Key.LeftShift or Key.RightShift or Key.LWin or Key.RWin or Key.System or Key.None)
            return;
        if (key == Key.Escape) return;

        var mods = Keyboard.Modifiers;
        bool isFunctionKey = key >= Key.F1 && key <= Key.F24;
        if (mods == ModifierKeys.None && !isFunctionKey) return; // require a modifier for normal keys

        var parts = new List<string>();
        if (mods.HasFlag(ModifierKeys.Control)) parts.Add("Ctrl");
        if (mods.HasFlag(ModifierKeys.Alt)) parts.Add("Alt");
        if (mods.HasFlag(ModifierKeys.Shift)) parts.Add("Shift");
        if (mods.HasFlag(ModifierKeys.Windows)) parts.Add("Win");
        parts.Add(key.ToString());

        HotkeyBox.Text = string.Join("+", parts);
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        _cfg.ServerUrl = ServerBox.Text.Trim();
        if (HotkeyBox.Text.Trim().Length > 0) _cfg.Hotkey = HotkeyBox.Text.Trim();
        _cfg.IdleTimeoutMinutes = ParseInt(IdleBox.Text, _cfg.IdleTimeoutMinutes, 0, 1440);
        _cfg.ClipboardClearSeconds = ParseInt(ClipBox.Text, _cfg.ClipboardClearSeconds, 0, 3600);
        _cfg.TypingDelayMs = ParseInt(DelayBox.Text, _cfg.TypingDelayMs, 0, 500);
        _cfg.ClearFieldBeforeTyping = ClearFieldChk.IsChecked == true;
        _cfg.ExcludeFromScreenCapture = ExcludeCapChk.IsChecked == true;
        _cfg.AntiDebugger = AntiDbgChk.IsChecked == true;

        _cfg.EnableTrayClick = TrayClickChk.IsChecked == true;
        _cfg.Autostart = AutostartChk.IsChecked == true;
        AutostartService.Set(_cfg.Autostart);

        int lsel = LangBox.SelectedIndex;
        _cfg.Language = (lsel >= 0 && lsel < _langCodes.Length) ? _langCodes[lsel] : "auto";

        DialogResult = true;
    }

    private void Reset_Click(object sender, RoutedEventArgs e)
    {
        var d = new AppConfig(); // defaults; the Server URL is kept on purpose
        HotkeyBox.Text = d.Hotkey;
        IdleBox.Text = d.IdleTimeoutMinutes.ToString();
        ClipBox.Text = d.ClipboardClearSeconds.ToString();
        DelayBox.Text = d.TypingDelayMs.ToString();
        ClearFieldChk.IsChecked = d.ClearFieldBeforeTyping;
        AutostartChk.IsChecked = d.Autostart;
        TrayClickChk.IsChecked = d.EnableTrayClick;
        ExcludeCapChk.IsChecked = d.ExcludeFromScreenCapture;
        AntiDbgChk.IsChecked = d.AntiDebugger;
        LangBox.SelectedIndex = 0;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static int ParseInt(string text, int fallback, int min, int max)
        => int.TryParse(text.Trim(), out int v) ? Math.Clamp(v, min, max) : fallback;
}
