using System.Runtime.InteropServices;

namespace VaultType.Security.Passkey;

// Native definitions for the Windows 11 passkey plugin authenticator API, transcribed from the
// official headers at github.com/microsoft/webauthn (pluginauthenticator.idl / webauthnplugin.h).
// Field order and sizes must match exactly - Windows passes raw pointers to these structs.

internal enum PluginRequestType
{
    Ctap2Cbor = 0x01,   // CBOR encoded CTAP2 message
}

internal enum PluginLockStatus
{
    Locked = 0,
    Unlocked = 1,
}

// WEBAUTHN_PLUGIN_OPERATION_REQUEST (x64: 56 bytes)
[StructLayout(LayoutKind.Sequential)]
internal struct PluginOperationRequest
{
    public IntPtr Hwnd;                  // top-level window of the caller
    public Guid TransactionId;
    public uint CbRequestSignature;
    public IntPtr PbRequestSignature;    // signature over the request, verifiable with the op-signing public key
    public PluginRequestType RequestType;
    public uint CbEncodedRequest;
    public IntPtr PbEncodedRequest;
}

// WEBAUTHN_PLUGIN_OPERATION_RESPONSE - the caller passes a pointer to this and we fill it in.
// The buffer must be allocated with CoTaskMemAlloc so the caller can free it.
[StructLayout(LayoutKind.Sequential)]
internal struct PluginOperationResponse
{
    public uint CbEncodedResponse;
    public IntPtr PbEncodedResponse;
}

// WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST
[StructLayout(LayoutKind.Sequential)]
internal struct PluginCancelOperationRequest
{
    public Guid TransactionId;
    public uint CbRequestSignature;
    public IntPtr PbRequestSignature;
}

// IPluginAuthenticator - the COM interface Windows calls into for a passkey ceremony.
// Declared as a plain (non-ComImport) interface because VaultType *implements* it; the CLR builds
// the vtable in declaration order after IUnknown. PreserveSig so we can return CTAP-mapped HRESULTs.
[ComVisible(true)]
[Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IPluginAuthenticator
{
    [PreserveSig] int MakeCredential(IntPtr request, IntPtr response);
    [PreserveSig] int GetAssertion(IntPtr request, IntPtr response);
    [PreserveSig] int CancelOperation(IntPtr request);
    [PreserveSig] int GetLockStatus(out int lockStatus);
}

// IClassFactory - implemented (not imported), so Windows can activate our COM class.
[ComVisible(true)]
[Guid("00000001-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IClassFactory
{
    [PreserveSig] int CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject);
    [PreserveSig] int LockServer([MarshalAs(UnmanagedType.Bool)] bool fLock);
}

// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2 - the "_2" variant takes the CLSID by pointer and
// adds the Hello user-verification key name, which is what we want.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct PluginAddAuthenticatorOptions2
{
    [MarshalAs(UnmanagedType.LPWStr)] public string AuthenticatorName;
    public IntPtr Clsid;                                              // const CLSID*
    [MarshalAs(UnmanagedType.LPWStr)] public string? PluginRpId;
    [MarshalAs(UnmanagedType.LPWStr)] public string? LightThemeLogoSvg;   // base64 SVG 1.1
    [MarshalAs(UnmanagedType.LPWStr)] public string? DarkThemeLogoSvg;
    public uint CbAuthenticatorInfo;
    public IntPtr PbAuthenticatorInfo;                                // CTAP CBOR authenticatorGetInfo
    public uint CSupportedRpIds;                                      // 0 = all RPs supported
    public IntPtr PpwszSupportedRpIds;
    [MarshalAs(UnmanagedType.LPWStr)] public string? UserVerificationKeyName;
}

// WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS - metadata cache entry for the Windows passkey picker.
// Windows only offers a plugin's discoverable credentials in username-less flows when they have
// been announced through WebAuthNPluginAuthenticatorAddCredentials; every field is required.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct PluginCredentialDetails
{
    public uint CbCredentialId;
    public IntPtr PbCredentialId;
    [MarshalAs(UnmanagedType.LPWStr)] public string RpId;
    [MarshalAs(UnmanagedType.LPWStr)] public string RpName;
    public uint CbUserId;
    public IntPtr PbUserId;
    [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    [MarshalAs(UnmanagedType.LPWStr)] public string UserDisplayName;
}

// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE - Windows returns the public key it uses to sign
// operation requests, so the plugin can verify that a ceremony really came from Windows.
[StructLayout(LayoutKind.Sequential)]
internal struct PluginAddAuthenticatorResponse
{
    public uint CbOpSignPubKey;
    public IntPtr PbOpSignPubKey;
}

// WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST - the v1 variant without the optional buffer-to-sign,
// which is what the official Passkey Manager sample uses. All strings must be non-null; the v2
// call rejects the request with E_POINTER otherwise.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct PluginUserVerificationRequest
{
    public IntPtr Hwnd;
    public IntPtr PGuidTransactionId;                      // REFGUID (const GUID*)
    [MarshalAs(UnmanagedType.LPWStr)] public string? Username;
    [MarshalAs(UnmanagedType.LPWStr)] public string? DisplayHint;
}

internal enum PluginAuthenticatorState
{
    Disabled = 0,
    Enabled = 1,
}

internal static class PasskeyNative
{
    private const string WebAuthn = "webauthn.dll";
    private const string Ole32 = "ole32.dll";
    private const string User32 = "user32.dll";

    // --- registration ---

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginAddAuthenticator2(
        ref PluginAddAuthenticatorOptions2 options, out IntPtr response);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern void WebAuthNPluginFreeAddAuthenticatorResponse(IntPtr response);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginRemoveAuthenticator(ref Guid rclsid);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginGetAuthenticatorState(
        ref Guid rclsid, out PluginAuthenticatorState state);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginAuthenticatorAddCredentials(
        ref Guid rclsid, uint cCredentialDetails, IntPtr pCredentialDetails);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginAuthenticatorRemoveAllCredentials(ref Guid rclsid);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginGetOperationSigningPublicKey(
        ref Guid rclsid, out uint cbOpSignPubKey, out IntPtr ppbOpSignPubKey);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern void WebAuthNPluginFreePublicKeyResponse(IntPtr pbOpSignPubKey);

    // --- Windows Hello user verification ---

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern int WebAuthNPluginPerformUserVerification(
        ref PluginUserVerificationRequest request, out uint cbResponse, out IntPtr ppbResponse);

    [DllImport(WebAuthn, CallingConvention = CallingConvention.StdCall)]
    internal static extern void WebAuthNPluginFreeUserVerificationResponse(IntPtr pbResponse);

    // --- COM server plumbing ---

    internal const uint CLSCTX_LOCAL_SERVER = 0x4;
    internal const uint REGCLS_MULTIPLEUSE = 1;
    internal const uint REGCLS_SUSPENDED = 4;
    internal const uint COINIT_APARTMENTTHREADED = 0x2;

    internal const int S_OK = 0;
    internal const int E_NOINTERFACE = unchecked((int)0x80004002);
    internal const int E_POINTER = unchecked((int)0x80004003);
    internal const int E_FAIL = unchecked((int)0x80004005);
    internal const int E_INVALIDARG = unchecked((int)0x80070057);
    internal const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
    // Lets Windows tell a user-cancelled ceremony apart from a plugin failure.
    internal const int NTE_USER_CANCELLED = unchecked((int)0x80090036);

    [DllImport(Ole32)]
    internal static extern int CoInitializeEx(IntPtr reserved, uint coInit);

    [DllImport(Ole32)]
    internal static extern void CoUninitialize();

    [DllImport(Ole32)]
    internal static extern int CoRegisterClassObject(
        ref Guid rclsid, [MarshalAs(UnmanagedType.IUnknown)] object pUnk,
        uint dwClsContext, uint flags, out uint lpdwRegister);

    [DllImport(Ole32)]
    internal static extern int CoRevokeClassObject(uint dwRegister);

    [DllImport(Ole32)]
    internal static extern int CoResumeClassObjects();

    [StructLayout(LayoutKind.Sequential)]
    internal struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport(User32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PeekMessage(out MSG msg, IntPtr hWnd, uint min, uint max, uint remove);

    [DllImport(User32)]
    internal static extern bool TranslateMessage(ref MSG msg);

    [DllImport(User32)]
    internal static extern IntPtr DispatchMessage(ref MSG msg);
}
