using System.Runtime.InteropServices;

namespace VaultType.Security.Passkey;

// Registers/unregisters VaultType as a Windows 11 passkey plugin authenticator. Only meaningful
// when the app runs from its MSIX package (the com:ExeServer CLSID must be registered); running the
// plain exe cannot serve the COM object, so registration is skipped there.
//
// Once registered, VaultType shows up in Settings > Accounts > Passkeys and in the browser's
// passkey picker, and Windows activates "VaultType.exe -PluginActivated" (PasskeyComHost) whenever
// a site runs a ceremony against it.
public static class PasskeyProvider
{
    // The plugin authenticator API shipped in Windows 11 24H2 (build 26100); the plugin COM
    // server can only be activated by Windows when the app has a package identity.
    public static bool Supported => AppInfo.IsPackaged && Environment.OSVersion.Version.Build >= 26100;

    // Whether Windows currently has us registered as an enabled authenticator.
    public static bool Registered
    {
        get
        {
            if (!Supported) return false;
            try
            {
                // The state query succeeds only for a registered plugin (NTE_NOT_FOUND otherwise).
                // Enabled/Disabled is the user's toggle in Windows Settings > Passkeys > Advanced
                // options - a disabled plugin is still registered, so don't re-register it.
                var clsid = PasskeyIds.Clsid;
                int hr = PasskeyNative.WebAuthNPluginGetAuthenticatorState(ref clsid, out _);
                return hr == PasskeyNative.S_OK;
            }
            catch { return false; }
        }
    }

    // Enable/disable the provider. Safe to call from the settings toggle: it never throws, and it is
    // a no-op when running unpackaged or on an older Windows.
    public static void Apply(bool enabled)
    {
        if (!Supported) return;

        try
        {
            if (enabled)
            {
                if (Registered) return;
                Register();
            }
            else
            {
                Unregister();
            }
        }
        catch
        {
        }
    }

    private static void Register()
    {
        byte[] info = Ctap2.BuildAuthenticatorInfo();
        IntPtr pInfo = Marshal.AllocHGlobal(info.Length);
        IntPtr pClsid = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        IntPtr response = IntPtr.Zero;
        try
        {
            Marshal.Copy(info, 0, pInfo, info.Length);
            Marshal.StructureToPtr(PasskeyIds.Clsid, pClsid, fDeleteOld: false);

            var options = new PluginAddAuthenticatorOptions2
            {
                AuthenticatorName = PasskeyIds.AuthenticatorName,
                Clsid = pClsid,
                // Despite the header calling it optional, webauthn.dll rejects a null RP ID with
                // E_INVALIDARG. Only used for nested WebAuthn calls from the plugin itself (which
                // VaultType never makes), so the value just has to be a well-formed RP ID.
                PluginRpId = PasskeyIds.PluginRpId,
                LightThemeLogoSvg = null,
                DarkThemeLogoSvg = null,
                CbAuthenticatorInfo = (uint)info.Length,
                PbAuthenticatorInfo = pInfo,
                CSupportedRpIds = 0,          // 0 = every relying party
                PpwszSupportedRpIds = IntPtr.Zero,
                // Must stay null until we create that Hello key via
                // KeyCredentialManager.RequestCreateAsync - naming a nonexistent key fails the
                // whole registration with NTE_INVALID_PARAMETER (0x80090027).
                UserVerificationKeyName = null,
            };

            PasskeyNative.WebAuthNPluginAddAuthenticator2(ref options, out response);
            // The response carries the public key Windows signs operation requests with; we fetch it
            // on demand in the plugin process (OperationSignature), so nothing needs persisting here.
        }
        finally
        {
            if (response != IntPtr.Zero) PasskeyNative.WebAuthNPluginFreeAddAuthenticatorResponse(response);
            Marshal.FreeHGlobal(pClsid);
            Marshal.FreeHGlobal(pInfo);
        }
    }

    // Mirror the vault's discoverable passkeys into Windows' credential metadata cache. Without
    // this, a username-less ceremony (empty allowList) shows "no passkeys available": the picker
    // only lists what the plugin announced. Only metadata crosses this API - no key material.
    public static void SyncCredentialMetadata(IReadOnlyList<Models.Fido2Entry> creds)
    {
        if (!Supported) return;
        var clsid = PasskeyIds.Clsid;
        try
        {
            PasskeyNative.WebAuthNPluginAuthenticatorRemoveAllCredentials(ref clsid);

            var list = creds.Where(c => c.Discoverable && c.CredentialId.Length > 0 && c.RpId.Length > 0).ToList();
            if (list.Count == 0) return;

            int size = Marshal.SizeOf<PluginCredentialDetails>();
            IntPtr array = Marshal.AllocHGlobal(size * list.Count);
            var blobs = new List<IntPtr>();
            try
            {
                for (int i = 0; i < list.Count; i++)
                {
                    var c = list[i];
                    IntPtr pCred = Marshal.AllocHGlobal(c.CredentialId.Length);
                    blobs.Add(pCred);
                    Marshal.Copy(c.CredentialId, 0, pCred, c.CredentialId.Length);

                    // Every field is required; fall back to something sensible rather than null.
                    byte[] userId = c.UserHandle.Length > 0 ? c.UserHandle : c.CredentialId;
                    IntPtr pUser = Marshal.AllocHGlobal(userId.Length);
                    blobs.Add(pUser);
                    Marshal.Copy(userId, 0, pUser, userId.Length);

                    var details = new PluginCredentialDetails
                    {
                        CbCredentialId = (uint)c.CredentialId.Length,
                        PbCredentialId = pCred,
                        RpId = c.RpId,
                        RpName = c.RpName.Length > 0 ? c.RpName : c.RpId,
                        CbUserId = (uint)userId.Length,
                        PbUserId = pUser,
                        UserName = c.UserName.Length > 0 ? c.UserName : c.ItemName,
                        UserDisplayName = c.UserDisplayName.Length > 0 ? c.UserDisplayName
                            : (c.UserName.Length > 0 ? c.UserName : c.ItemName),
                    };
                    Marshal.StructureToPtr(details, array + i * size, fDeleteOld: false);
                }

                PasskeyNative.WebAuthNPluginAuthenticatorAddCredentials(ref clsid, (uint)list.Count, array);
            }
            finally
            {
                for (int i = 0; i < list.Count; i++)
                    Marshal.DestroyStructure<PluginCredentialDetails>(array + i * size);
                foreach (var p in blobs) Marshal.FreeHGlobal(p);
                Marshal.FreeHGlobal(array);
            }
        }
        catch
        {
        }
    }

    private static void Unregister()
    {
        var clsid = PasskeyIds.Clsid;
        PasskeyNative.WebAuthNPluginRemoveAuthenticator(ref clsid);
    }
}
