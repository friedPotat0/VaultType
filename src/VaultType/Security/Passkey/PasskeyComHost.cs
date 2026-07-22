using System.Runtime.InteropServices;

namespace VaultType.Security.Passkey;

// Entry point when Windows activates the MSIX-declared COM server ("VaultType.exe -PluginActivated")
// to serve the IPluginAuthenticator object for a passkey ceremony.
//
// Lifetime: register the class factory, pump messages while Windows drives the ceremony, and exit
// once nothing has happened for IdleTimeout. Windows starts a fresh process for the next ceremony,
// so exiting is cheap - and it means no vault state outlives the operation that needed it.
public static class PasskeyComHost
{
    // Long enough that the follow-up calls of one ceremony reuse this process (Windows may call
    // GetLockStatus, then GetAssertion, then CancelOperation), short enough not to linger.
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(120);

    private static long _lastActivityTicks = DateTime.UtcNow.Ticks;
    private static int _lockCount;

    // Called on every incoming COM call so an in-flight ceremony keeps the server alive.
    internal static void Touch() => Volatile.Write(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

    internal static void LockServer(bool fLock)
    {
        if (fLock) Interlocked.Increment(ref _lockCount);
        else Interlocked.Decrement(ref _lockCount);
        Touch();
    }

    public static void Run()
    {
        // STA: the ceremony may put a window on screen (unlock / confirmation), and the message
        // pump below is what keeps that window responsive.
        int hr = PasskeyNative.CoInitializeEx(IntPtr.Zero, PasskeyNative.COINIT_APARTMENTTHREADED);
        if (hr < 0) return;

        uint cookie = 0;
        var clsid = PasskeyIds.Clsid;
        try
        {
            hr = PasskeyNative.CoRegisterClassObject(
                ref clsid, new PluginClassFactory(),
                PasskeyNative.CLSCTX_LOCAL_SERVER,
                PasskeyNative.REGCLS_MULTIPLEUSE | PasskeyNative.REGCLS_SUSPENDED,
                out cookie);
            if (hr < 0) return;

            hr = PasskeyNative.CoResumeClassObjects();
            if (hr < 0) return;

            Touch();
            PumpUntilIdle();
        }
        catch
        {
        }
        finally
        {
            if (cookie != 0) PasskeyNative.CoRevokeClassObject(cookie);
            PasskeyNative.CoUninitialize();
        }
    }

    // Dispatch COM/window messages and shut down once the server has been idle long enough.
    // GetMessage would block indefinitely, so this uses PeekMessage plus a short sleep.
    private static void PumpUntilIdle()
    {
        const uint PM_REMOVE = 0x0001;
        const uint WM_QUIT = 0x0012;

        while (true)
        {
            while (PasskeyNative.PeekMessage(out var msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                if (msg.message == WM_QUIT) return;
                PasskeyNative.TranslateMessage(ref msg);
                PasskeyNative.DispatchMessage(ref msg);
            }

            var idle = DateTime.UtcNow - new DateTime(Volatile.Read(ref _lastActivityTicks), DateTimeKind.Utc);
            if (Volatile.Read(ref _lockCount) <= 0 && idle > IdleTimeout) return;

            Thread.Sleep(50);
        }
    }
}

// Hands Windows a PluginAuthenticator when it activates our CLSID.
[ComVisible(true)]
internal sealed class PluginClassFactory : IClassFactory
{
    public int CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject)
    {
        ppvObject = IntPtr.Zero;
        if (pUnkOuter != IntPtr.Zero) return PasskeyNative.CLASS_E_NOAGGREGATION;

        PasskeyComHost.Touch();
        try
        {
            IntPtr unk = Marshal.GetIUnknownForObject(new PluginAuthenticator());
            try { return Marshal.QueryInterface(unk, in riid, out ppvObject); }
            finally { Marshal.Release(unk); }
        }
        catch
        {
            return PasskeyNative.E_FAIL;
        }
    }

    public int LockServer(bool fLock)
    {
        PasskeyComHost.LockServer(fLock);
        return PasskeyNative.S_OK;
    }
}
