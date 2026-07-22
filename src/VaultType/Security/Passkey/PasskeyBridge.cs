using System.IO.Pipes;

namespace VaultType.Security.Passkey;

// Client side of PasskeyIpc, used by the plugin COM process. The tray instance holds the unlocked
// vault, so every ceremony is answered there; if no instance is running the ceremony fails with a
// clean CTAP status instead of prompting for a second unlock in a windowless COM process.
internal static class PasskeyBridge
{
    private const int ConnectTimeoutMs = 2000;

    internal static bool VaultUnlocked()
    {
        var resp = Send(new PasskeyIpcRequest { Op = "status" });
        return resp is { Ok: true, Unlocked: true };
    }

    internal static PasskeyIpcResponse Send(PasskeyIpcRequest request)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PasskeyIpc.PipeName, PipeDirection.InOut);
            pipe.Connect(ConnectTimeoutMs);
            // No read timeout: PipeStream does not support one (setting it throws), and a ceremony
            // may legitimately sit on the tray's unlock/confirmation window. Windows cancels a
            // stuck ceremony through CancelOperation, and the tray always answers or closes the
            // pipe, which unblocks the read.
            PasskeyIpc.WriteMessage(pipe, request);
            return PasskeyIpc.ReadMessage<PasskeyIpcResponse>(pipe)
                ?? PasskeyIpcResponse.Fail(CtapStatus.OtherError);
        }
        catch (TimeoutException)
        {
            return PasskeyIpcResponse.Fail(CtapStatus.OperationDenied);
        }
        catch
        {
            return PasskeyIpcResponse.Fail(CtapStatus.OtherError);
        }
    }
}
