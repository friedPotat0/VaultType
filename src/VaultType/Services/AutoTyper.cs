using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using VaultType.Models;
using VaultType.Security;

namespace VaultType.Services;

public enum TypeAction { Full, Username, Password, Totp }

// Types keystrokes into the window that was active before. Secrets are decrypted into a locked
// buffer only for the instant we type them and wiped right after - no clipboard involved. If
// focus leaves the target mid-sequence we stop immediately (KeePass-style), so stray characters
// never land in the wrong window.
public static class AutoTyper
{
    private sealed class FocusLost : Exception { }

    public static void Type(IntPtr target, VaultItem item, SecretProtector protector, TypeAction action, int delayMs, bool clearField)
    {
        if (action == TypeAction.Full && !string.IsNullOrWhiteSpace(item.CustomSequence))
        {
            TypeSequence(target, item, protector, item.CustomSequence!, delayMs, clearField);
            return;
        }

        try
        {
            RestoreFocus(target);   // aborts (FocusLost) if the target never comes to the foreground
            switch (action)
            {
                case TypeAction.Username:
                    ClearField(target, clearField);
                    TypeText(target, item.Username, delayMs);
                    break;

                case TypeAction.Password:
                    ClearField(target, clearField);
                    TypeSecret(target, item.Password, protector, delayMs);
                    break;

                case TypeAction.Totp:
                    ClearField(target, clearField);
                    TypeTotp(target, item, protector, delayMs);
                    break;

                default: // Full: username <Tab> password <Enter>
                    if (!string.IsNullOrEmpty(item.Username))
                    {
                        ClearField(target, clearField);
                        TypeText(target, item.Username, delayMs);
                        SendVk(target, Native.VK_TAB);
                    }
                    ClearField(target, clearField);
                    TypeSecret(target, item.Password, protector, delayMs);
                    SendVk(target, Native.VK_RETURN);
                    break;
            }
        }
        catch (FocusLost) { /* target window lost focus -> typing aborted */ }
    }

    // Runs a custom sequence template, e.g. {USERNAME}{TAB}{PASSWORD}{ENTER}.
    // Supported: {USERNAME}/{USER}, {PASSWORD}/{PASS}, {TOTP}, {TAB}, {ENTER}/{RETURN},
    // {SPACE}, {CLEARFIELD}, {DELAY n}; anything else is typed literally.
    private static void TypeSequence(IntPtr target, VaultItem item, SecretProtector protector, string template, int delayMs, bool clearField)
    {
        try
        {
            RestoreFocus(target);   // aborts (FocusLost) if the target never comes to the foreground
            int i = 0;
            while (i < template.Length)
            {
                if (template[i] == '{')
                {
                    int end = template.IndexOf('}', i + 1);
                    if (end < 0) { TypeText(target, template.Substring(i), delayMs); break; }
                    HandleToken(target, item, protector, template.Substring(i + 1, end - i - 1).Trim(), delayMs, clearField);
                    i = end + 1;
                }
                else
                {
                    int next = template.IndexOf('{', i);
                    if (next < 0) next = template.Length;
                    TypeText(target, template.Substring(i, next - i), delayMs);
                    i = next;
                }
            }
        }
        catch (FocusLost) { /* target window lost focus -> typing aborted */ }
    }

    private static void HandleToken(IntPtr target, VaultItem item, SecretProtector protector, string token, int delayMs, bool clearField)
    {
        if (token.Length == 0) return;
        string name = token, arg = "";
        int sep = token.IndexOfAny(new[] { ' ', '=' });
        if (sep >= 0) { name = token.Substring(0, sep).Trim(); arg = token.Substring(sep + 1).Trim(); }

        switch (name.ToUpperInvariant())
        {
            case "USERNAME": case "USER": case "LOGIN": TypeText(target, item.Username, delayMs); break;
            case "PASSWORD": case "PASS": TypeSecret(target, item.Password, protector, delayMs); break;
            case "TOTP": case "OTP": TypeTotp(target, item, protector, delayMs); break;
            case "TAB": SendVk(target, Native.VK_TAB); break;
            case "ENTER": case "RETURN": SendVk(target, Native.VK_RETURN); break;
            case "SPACE": TypeText(target, " ", delayMs); break;
            case "CLEARFIELD": ClearField(target, true); break;
            case "DELAY": case "WAIT": case "SLEEP":
                if (int.TryParse(arg, out int ms)) { Guard(target); Thread.Sleep(Math.Clamp(ms, 0, 60000)); }
                break;
            default: TypeText(target, "{" + token + "}", delayMs); break; // unknown -> literal
        }
    }

    // Bring the target window back to the foreground and confirm it actually took focus before
    // we send a single keystroke. SetForegroundWindow can silently fail (foreground lock, the
    // window went away, focus-stealing prevention), so we don't trust its result blindly and we
    // don't just sleep-and-hope: we poll GetForegroundWindow until the switch is confirmed or a
    // short timeout elapses, and abort (FocusLost) rather than risk typing into the wrong window.
    private static void RestoreFocus(IntPtr target)
    {
        if (target == IntPtr.Zero) throw new FocusLost();
        if (Native.GetForegroundWindow() == target) return;

        Native.SetForegroundWindow(target);

        const int timeoutMs = 500, stepMs = 10;
        for (int waited = 0; waited < timeoutMs; waited += stepMs)
        {
            if (Native.GetForegroundWindow() == target) return;
            Thread.Sleep(stepMs);
        }
        throw new FocusLost();
    }

    // bail out the moment the foreground window isn't our target any more
    private static void Guard(IntPtr target)
    {
        if (Native.GetForegroundWindow() != target) throw new FocusLost();
    }

    private static void TypeText(IntPtr target, string text, int delayMs)
    {
        foreach (char c in text)
        {
            Guard(target);
            SendUnit(c);
            if (delayMs > 0) Thread.Sleep(delayMs);
        }
    }

    private static void TypeSecret(IntPtr target, SecretBox? box, SecretProtector protector, int delayMs)
    {
        if (box == null || !protector.IsActive) return;
        using LockedBuffer plain = protector.Reveal(box);           // UTF-8 plaintext in locked memory
        int byteLen = box.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);          // UTF-16 in locked memory
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        for (int i = 0; i < n; i++)
        {
            Guard(target);                                          // abort if focus left the target
            SendUnit(charSpan[i]);
            if (delayMs > 0) Thread.Sleep(delayMs);
        }
        // 'chars' and 'plain' are zeroed on dispose
    }

    private static void TypeTotp(IntPtr target, VaultItem item, SecretProtector protector, int delayMs)
    {
        if (item.TotpSecret == null || !protector.IsActive) return;
        using LockedBuffer plain = protector.Reveal(item.TotpSecret);   // UTF-8 seed in locked memory
        int byteLen = item.TotpSecret.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);              // UTF-16 seed, also locked
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        string? code = Totp.Compute(charSpan.Slice(0, n));             // seed never becomes a managed string
        if (code != null) TypeText(target, code, delayMs);
    }

    // Ctrl+A the field first so what we type overwrites whatever was already there
    private static void ClearField(IntPtr target, bool enabled)
    {
        if (!enabled) return;
        Guard(target);
        const ushort VK_CONTROL = 0x11, VK_A = 0x41;
        var inputs = new[]
        {
            MakeKey(VK_CONTROL, false),
            MakeKey(VK_A, false),
            MakeKey(VK_A, true),
            MakeKey(VK_CONTROL, true),
        };
        Native.SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<Native.INPUT>());
        Thread.Sleep(25);
    }

    // Sends a single UTF-16 code unit as a Unicode keystroke.
    private static void SendUnit(char unit)
    {
        var inputs = new Native.INPUT[2];
        inputs[0].type = Native.INPUT_KEYBOARD;
        inputs[0].u.ki = new Native.KEYBDINPUT { wVk = 0, wScan = unit, dwFlags = Native.KEYEVENTF_UNICODE };
        inputs[1].type = Native.INPUT_KEYBOARD;
        inputs[1].u.ki = new Native.KEYBDINPUT { wVk = 0, wScan = unit, dwFlags = Native.KEYEVENTF_UNICODE | Native.KEYEVENTF_KEYUP };
        Native.SendInput(2, inputs, Marshal.SizeOf<Native.INPUT>());
    }

    private static void SendVk(IntPtr target, ushort vk)
    {
        Guard(target);
        var inputs = new[] { MakeKey(vk, false), MakeKey(vk, true) };
        Native.SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<Native.INPUT>());
    }

    private static Native.INPUT MakeKey(ushort vk, bool keyUp) => new()
    {
        type = Native.INPUT_KEYBOARD,
        u = new Native.INPUTUNION { ki = new Native.KEYBDINPUT { wVk = vk, wScan = 0, dwFlags = keyUp ? Native.KEYEVENTF_KEYUP : 0 } }
    };
}
