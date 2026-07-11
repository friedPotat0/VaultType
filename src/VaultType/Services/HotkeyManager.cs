using System.Windows.Input;
using System.Windows.Interop;
using VaultType.Security;

namespace VaultType.Services;

// Registers a global hotkey via a message-only window.
public sealed class HotkeyManager : IDisposable
{
    private const int HotkeyId = 0xB17;
    private static readonly IntPtr HWND_MESSAGE = new(-3);

    private HwndSource? _source;
    public event Action? Pressed;

    public bool Register(string hotkey, out string error)
    {
        error = "";
        if (!TryParse(hotkey, out uint mods, out uint vk))
        {
            error = $"Invalid hotkey: \"{hotkey}\"";
            return false;
        }

        _source ??= CreateSource();
        Native.UnregisterHotKey(_source.Handle, HotkeyId);
        if (!Native.RegisterHotKey(_source.Handle, HotkeyId, mods | Native.MOD_NOREPEAT, vk))
        {
            error = $"Hotkey \"{hotkey}\" is already in use.";
            return false;
        }
        return true;
    }

    private HwndSource CreateSource()
    {
        var src = new HwndSource(new HwndSourceParameters("BwatHotkey")
        {
            ParentWindow = HWND_MESSAGE,
            WindowStyle = 0,
        });
        src.AddHook(WndProc);
        return src;
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == Native.WM_HOTKEY && wParam.ToInt32() == HotkeyId)
        {
            handled = true;
            Pressed?.Invoke();
        }
        return IntPtr.Zero;
    }

    public static bool TryParse(string hotkey, out uint mods, out uint vk)
    {
        mods = 0; vk = 0;
        if (string.IsNullOrWhiteSpace(hotkey)) return false;
        foreach (var raw in hotkey.Split('+'))
        {
            var part = raw.Trim();
            switch (part.ToLowerInvariant())
            {
                case "ctrl": case "control": mods |= Native.MOD_CONTROL; break;
                case "alt": mods |= Native.MOD_ALT; break;
                case "shift": mods |= Native.MOD_SHIFT; break;
                case "win": case "windows": mods |= Native.MOD_WIN; break;
                default:
                    if (Enum.TryParse<Key>(part, true, out var key))
                    {
                        int vkey = KeyInterop.VirtualKeyFromKey(key);
                        if (vkey != 0) vk = (uint)vkey;
                    }
                    break;
            }
        }
        return mods != 0 && vk != 0;
    }

    // drop the hotkey for now but keep the message window around
    public void Unregister()
    {
        if (_source != null) Native.UnregisterHotKey(_source.Handle, HotkeyId);
    }

    public void Dispose()
    {
        if (_source != null)
        {
            Native.UnregisterHotKey(_source.Handle, HotkeyId);
            _source.RemoveHook(WndProc);
            _source.Dispose();
            _source = null;
        }
    }
}
