using System.Windows.Threading;
using VaultType.Security;

namespace VaultType.Services;

// Fires the auto-lock after a stretch of inactivity. Uses the wall clock so standby,
// screen lock and long absences all count. Process exit (reboot, logoff) locks anyway,
// since the RAM is gone.
public sealed class IdleLockService : IDisposable
{
    private readonly DispatcherTimer _timer;
    private int _timeoutMinutes;
    private uint _lastInputTick;
    private DateTime _lastActivity;
    private bool _armed;

    public event Action? Lock;

    public IdleLockService(int timeoutMinutes)
    {
        _timeoutMinutes = timeoutMinutes;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        _timer.Tick += Tick;
    }

    public void Arm(int timeoutMinutes)
    {
        _timeoutMinutes = timeoutMinutes;
        _lastActivity = DateTime.UtcNow;
        _lastInputTick = CurrentInputTick();
        _armed = true;
        _timer.Start();
    }

    public void Disarm()
    {
        _armed = false;
        _timer.Stop();
    }

    private void Tick(object? sender, EventArgs e)
    {
        if (!_armed || _timeoutMinutes <= 0) return;

        uint tick = CurrentInputTick();
        if (tick != _lastInputTick)
        {
            _lastInputTick = tick;
            _lastActivity = DateTime.UtcNow;   // there was input
        }

        if (DateTime.UtcNow - _lastActivity >= TimeSpan.FromMinutes(_timeoutMinutes))
        {
            Disarm();
            Lock?.Invoke();
        }
    }

    private static uint CurrentInputTick()
    {
        var lii = new Native.LASTINPUTINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.LASTINPUTINFO>() };
        return Native.GetLastInputInfo(ref lii) ? lii.dwTime : Native.GetTickCount();
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= Tick;
    }
}
