using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VaultType.Security;

// Unmanaged buffer kept out of the pagefile via VirtualLock and zeroed on Dispose.
// (NativeMemory.Clear won't be optimised away by the JIT.) Holds plaintext secrets briefly.
public sealed unsafe class LockedBuffer : IDisposable
{
    private IntPtr _ptr;
    public int Length { get; private set; }

    public LockedBuffer(int length)
    {
        if (length <= 0) length = 1;
        Length = length;
        _ptr = Native.VirtualAlloc(IntPtr.Zero, (UIntPtr)(uint)length,
            Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
        if (_ptr == IntPtr.Zero) throw new OutOfMemoryException("VirtualAlloc failed");
        // Best effort: VirtualLock can fail when the process working-set limit is hit. We keep
        // the buffer regardless (never throw); the return value is only surfaced as a debug hint.
        if (!Native.VirtualLock(_ptr, (UIntPtr)(uint)length))
            Debug.WriteLine($"LockedBuffer: VirtualLock failed (working-set limit?), err={Marshal.GetLastWin32Error()}");
        NativeMemory.Clear((void*)_ptr, (nuint)length);
    }

    public Span<byte> Span => new((void*)_ptr, Length);
    public IntPtr Ptr => _ptr;

    // grow into a bigger buffer; the old one is zeroed and freed
    public LockedBuffer Grow(int usedBytes)
    {
        // Guard the doubling against Int32 overflow, which would otherwise wrap to a
        // negative/tiny size and silently collapse the buffer to 1 byte.
        if (Length > int.MaxValue / 2)
            throw new OverflowException("LockedBuffer.Grow: doubling the buffer would overflow Int32.");
        var next = new LockedBuffer(Length * 2);
        Span.Slice(0, usedBytes).CopyTo(next.Span);
        Dispose();
        return next;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // Backstop: if Dispose() was forgotten, the finalizer still zeroes the plaintext and
    // frees the page so no un-wiped secret is left behind.
    ~LockedBuffer() => Dispose(false);

    private void Dispose(bool disposing)
    {
        if (_ptr == IntPtr.Zero) return;
        NativeMemory.Clear((void*)_ptr, (nuint)Length);
        Native.VirtualUnlock(_ptr, (UIntPtr)(uint)Length);
        Native.VirtualFree(_ptr, UIntPtr.Zero, Native.MEM_RELEASE);
        _ptr = IntPtr.Zero;
        Length = 0;
    }
}
