using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace VaultType.Security;

// Runs bw.exe carefully:
//  - the secret (master password / session key) goes in through a locked UTF-16 env block,
//    not the command line (which shows up in the process list), not our own environment,
//    and never as a managed string.
//  - stdout is read byte-by-byte into a LockedBuffer so the `list items` plaintext never
//    ends up as a managed string on the GC heap.
internal static class NativeProcess
{
    public sealed class Result : IDisposable
    {
        public LockedBuffer StdOut;
        public int StdOutLength;
        public string StdErr;
        public int ExitCode;
        public Result(LockedBuffer o, int len, string e, int code) { StdOut = o; StdOutLength = len; StdErr = e; ExitCode = code; }
        public ReadOnlySpan<byte> OutSpan => StdOut.Span.Slice(0, StdOutLength);
        public void Dispose() => StdOut.Dispose();
    }

    public static Result Run(string exePath, string args, IReadOnlyDictionary<string, string> plainEnv,
                             string? secretName = null, SecureString? secretValue = null, byte[]? stdin = null)
    {
        var sa = new Native.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>(),
            bInheritHandle = 1
        };
        if (!Native.CreatePipe(out IntPtr outRead, out IntPtr outWrite, ref sa, 0)) throw new Win32Exception();
        if (!Native.CreatePipe(out IntPtr errRead, out IntPtr errWrite, ref sa, 0)) throw new Win32Exception();
        Native.SetHandleInformation(outRead, Native.HANDLE_FLAG_INHERIT, 0);
        Native.SetHandleInformation(errRead, Native.HANDLE_FLAG_INHERIT, 0);

        IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero;
        if (stdin != null)
        {
            if (!Native.CreatePipe(out inRead, out inWrite, ref sa, 0)) throw new Win32Exception();
            Native.SetHandleInformation(inWrite, Native.HANDLE_FLAG_INHERIT, 0); // don't inherit the write end
        }

        LockedBuffer envBlock = BuildEnvBlock(plainEnv, secretName, secretValue);

        try
        {
            var si = new Native.STARTUPINFO
            {
                cb = Marshal.SizeOf<Native.STARTUPINFO>(),
                dwFlags = Native.STARTF_USESTDHANDLES,
                hStdInput = inRead,
                hStdOutput = outWrite,
                hStdError = errWrite,
            };

            string cmd = "\"" + exePath + "\" " + args;
            char[] cmdLine = new char[cmd.Length + 1];
            cmd.CopyTo(0, cmdLine, 0, cmd.Length);

            uint flags = Native.CREATE_NO_WINDOW | Native.CREATE_UNICODE_ENVIRONMENT;

            if (!Native.CreateProcessW(null, cmdLine, IntPtr.Zero, IntPtr.Zero,
                    bInheritHandles: true, flags, envBlock.Ptr, null, ref si, out var pi))
                throw new Win32Exception();

            // close the write ends in the parent -> reads get EOF
            Native.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            Native.CloseHandle(errWrite); errWrite = IntPtr.Zero;

            if (stdin != null)
            {
                Native.CloseHandle(inRead); inRead = IntPtr.Zero;
                try
                {
                    using var fs = new FileStream(new SafeFileHandle(inWrite, ownsHandle: false), FileAccess.Write);
                    fs.Write(stdin, 0, stdin.Length);
                    fs.Flush();
                }
                catch { }
                Native.CloseHandle(inWrite); inWrite = IntPtr.Zero;
            }

            var errTask = System.Threading.Tasks.Task.Run(() => ReadAllText(errRead));
            var (outBuf, outLen) = ReadAllBytesLocked(outRead);
            string stderr = errTask.GetAwaiter().GetResult();

            Native.WaitForSingleObject(pi.hProcess, Native.INFINITE);
            Native.GetExitCodeProcess(pi.hProcess, out uint code);
            Native.CloseHandle(pi.hThread);
            Native.CloseHandle(pi.hProcess);

            return new Result(outBuf, outLen, stderr, (int)code);
        }
        finally
        {
            envBlock.Dispose(); // wipe the master password / session from the environment block
            if (inRead != IntPtr.Zero) Native.CloseHandle(inRead);
            if (inWrite != IntPtr.Zero) Native.CloseHandle(inWrite);
            if (outRead != IntPtr.Zero) Native.CloseHandle(outRead);
            if (errRead != IntPtr.Zero) Native.CloseHandle(errRead);
            if (outWrite != IntPtr.Zero) Native.CloseHandle(outWrite);
            if (errWrite != IntPtr.Zero) Native.CloseHandle(errWrite);
        }
    }

    private static (LockedBuffer, int) ReadAllBytesLocked(IntPtr readHandle)
    {
        var buf = new LockedBuffer(64 * 1024);
        int used = 0;
        using var fs = new FileStream(new SafeFileHandle(readHandle, ownsHandle: false), FileAccess.Read);
        while (true)
        {
            if (used == buf.Length) buf = buf.Grow(used);
            int n = fs.Read(buf.Span.Slice(used));
            if (n <= 0) break;
            used += n;
        }
        return (buf, used);
    }

    private static string ReadAllText(IntPtr readHandle)
    {
        try
        {
            using var fs = new FileStream(new SafeFileHandle(readHandle, ownsHandle: false), FileAccess.Read);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            return sr.ReadToEnd();
        }
        catch { return ""; }
    }

    private static LockedBuffer BuildEnvBlock(IReadOnlyDictionary<string, string> plain,
                                              string? secretName, SecureString? secret)
    {
        int chars = 0;
        foreach (var kv in plain) chars += kv.Key.Length + 1 + kv.Value.Length + 1;
        if (secretName != null && secret != null) chars += secretName.Length + 1 + secret.Length + 1;
        chars += 1; // trailing second null

        var buf = new LockedBuffer(checked(chars * 2));
        var span = MemoryMarshal.Cast<byte, char>(buf.Span);
        int pos = 0;

        foreach (var kv in plain)
        {
            pos = Write(span, pos, kv.Key);
            span[pos++] = '=';
            pos = Write(span, pos, kv.Value);
            span[pos++] = '\0';
        }

        if (secretName != null && secret != null)
        {
            pos = Write(span, pos, secretName);
            span[pos++] = '=';
            IntPtr bstr = Marshal.SecureStringToGlobalAllocUnicode(secret);
            try
            {
                for (int i = 0; i < secret.Length; i++)
                    span[pos++] = (char)Marshal.ReadInt16(bstr, i * 2);
            }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(bstr); }
            span[pos++] = '\0';
        }

        span[pos] = '\0';
        return buf;
    }

    private static int Write(Span<char> dst, int pos, string s)
    {
        s.AsSpan().CopyTo(dst.Slice(pos));
        return pos + s.Length;
    }
}
