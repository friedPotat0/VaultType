using System.Runtime.InteropServices;

namespace VaultType.Security.Passkey;

// The COM object Windows drives during a passkey ceremony. Windows hands us a CTAP2 CBOR request
// (command byte + map) and expects the bare CBOR response map back - WITHOUT the CTAP status byte
// (confirmed against webauthn.dll's own WebAuthNEncodeMakeCredentialResponse output). Failures are
// reported as the HRESULT of the COM call, not as a CTAP status payload.
//
// Everything here runs in the "-PluginActivated" process (see PasskeyComHost), so it must never
// throw across the COM boundary - a managed exception escaping a [PreserveSig] method would tear
// down the ceremony with an opaque error instead of a CTAP status the browser can report.
[ComVisible(true)]
[Guid(PasskeyIds.ClsidString)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class PluginAuthenticator : IPluginAuthenticator
{
    public int MakeCredential(IntPtr request, IntPtr response)
        => Handle(request, response, Ceremony.MakeCredential);

    public int GetAssertion(IntPtr request, IntPtr response)
        => Handle(request, response, Ceremony.GetAssertion);

    // Windows calls this when the user aborts (or the ceremony times out). The ceremony code polls
    // the cancellation token. Unlike MakeCredential/GetAssertion this does NOT verify the request
    // signature: the only effect is aborting an in-flight ceremony, and the transaction id is a
    // 128-bit random GUID a caller would have to already know - so the blast radius is a self-DoS,
    // not a security bypass. (Signature verification isn't added here because the exact bytes
    // Windows signs for a cancel request aren't documented and can't be reproduced reliably.)
    public int CancelOperation(IntPtr request)
    {
        PasskeyComHost.Touch();
        try
        {
            if (request == IntPtr.Zero) return PasskeyNative.E_POINTER;
            var req = Marshal.PtrToStructure<PluginCancelOperationRequest>(request);
            Ceremony.Cancel(req.TransactionId);
            return PasskeyNative.S_OK;
        }
        catch
        {
            return PasskeyNative.E_FAIL;
        }
    }

    // Reported in the Windows passkey UI: a locked vault is shown as locked rather than as an
    // authenticator with no credentials.
    public int GetLockStatus(out int lockStatus)
    {
        lockStatus = (int)PluginLockStatus.Locked;
        PasskeyComHost.Touch();
        try
        {
            lockStatus = (int)(Ceremony.VaultUnlocked() ? PluginLockStatus.Unlocked : PluginLockStatus.Locked);
            return PasskeyNative.S_OK;
        }
        catch
        {
            return PasskeyNative.S_OK;   // stay "locked" rather than failing the whole ceremony
        }
    }

    // Shared plumbing for the two ceremony entry points: unmarshal the request, verify it really
    // came from Windows, run the handler, and hand the CTAP response back as CoTaskMem memory
    // (the caller frees it).
    private static int Handle(IntPtr request, IntPtr response,
                              Func<Guid, IntPtr, ReadOnlyMemory<byte>, byte[]> handler)
    {
        if (request == IntPtr.Zero || response == IntPtr.Zero) return PasskeyNative.E_POINTER;
        PasskeyComHost.Touch();

        byte[] payload;
        try
        {
            var req = Marshal.PtrToStructure<PluginOperationRequest>(request);

            if (req.RequestType != PluginRequestType.Ctap2Cbor)
                return PasskeyNative.E_INVALIDARG;

            byte[] encoded = new byte[req.CbEncodedRequest];
            if (req.CbEncodedRequest > 0)
                Marshal.Copy(req.PbEncodedRequest, encoded, 0, encoded.Length);

            if (!OperationSignature.Verify(req, encoded))
                return PasskeyNative.E_INVALIDARG;

            payload = handler(req.TransactionId, req.Hwnd, encoded);
        }
        catch
        {
            return PasskeyNative.E_FAIL;
        }

        // Ceremony reports errors as a single CTAP status byte; Windows expects them as a failing
        // HRESULT instead of a payload.
        if (payload.Length == 1)
        {
            var status = (CtapStatus)payload[0];
            return status is CtapStatus.OperationDenied or CtapStatus.KeepAliveCancel
                ? PasskeyNative.NTE_USER_CANCELLED
                : PasskeyNative.E_FAIL;
        }

        try
        {
            IntPtr buf = Marshal.AllocCoTaskMem(payload.Length);
            Marshal.Copy(payload, 0, buf, payload.Length);
            Marshal.StructureToPtr(
                new PluginOperationResponse { CbEncodedResponse = (uint)payload.Length, PbEncodedResponse = buf },
                response, fDeleteOld: false);
            return PasskeyNative.S_OK;
        }
        catch
        {
            return PasskeyNative.E_FAIL;
        }
    }
}
