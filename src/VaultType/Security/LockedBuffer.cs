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
        Native.VirtualLock(_ptr, (UIntPtr)(uint)length); // best effort (working-set limit)
        NativeMemory.Clear((void*)_ptr, (nuint)length);
    }

    public Span<byte> Span => new((void*)_ptr, Length);
    public IntPtr Ptr => _ptr;

    // grow into a bigger buffer; the old one is zeroed and freed
    public LockedBuffer Grow(int usedBytes)
    {
        var next = new LockedBuffer(Length * 2);
        Span.Slice(0, usedBytes).CopyTo(next.Span);
        Dispose();
        return next;
    }

    public void Dispose()
    {
        if (_ptr == IntPtr.Zero) return;
        NativeMemory.Clear((void*)_ptr, (nuint)Length);
        Native.VirtualUnlock(_ptr, (UIntPtr)(uint)Length);
        Native.VirtualFree(_ptr, UIntPtr.Zero, Native.MEM_RELEASE);
        _ptr = IntPtr.Zero;
        Length = 0;
    }
}
