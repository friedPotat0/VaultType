namespace VaultType.Security.Passkey;

// Stable identity for the Windows 11 passkey plugin authenticator. The CLSID is the COM class the
// MSIX package registers (see packaging/msix/AppxManifest.xml) and that WebAuthNPluginAddAuthenticator
// binds to; the AAGUID identifies this authenticator model to relying parties. Generated once - do
// not change after shipping, or existing passkeys stop resolving.
public static class PasskeyIds
{
    // COM server CLSID (matches <com:Class Id="..."> in the MSIX manifest)
    public const string ClsidString = "2d201497-f4f9-4bf0-b3c7-c230d332788d";
    public static readonly Guid Clsid = new(ClsidString);

    // FIDO2 authenticator AAGUID
    public const string AaguidString = "9ec060a7-bb97-4b30-98fa-2c72d5f43720";
    public static readonly Guid Aaguid = new(AaguidString);

    // AAGUID as 16 big-endian bytes (RFC 4122 order), for the CTAP authenticatorGetInfo response.
    public static readonly byte[] AaguidBytes =
    {
        0x9e, 0xc0, 0x60, 0xa7, 0xbb, 0x97, 0x4b, 0x30, 0x98, 0xfa, 0x2c, 0x72, 0xd5, 0xf4, 0x37, 0x20,
    };

    // Shown in Windows Settings > Accounts > Passkeys and in the WebAuthn provider picker.
    public const string AuthenticatorName = "VaultType";

    // RP ID for nested WebAuthn calls originating from the plugin itself. VaultType never makes
    // such calls, but webauthn.dll requires a non-null value at registration time.
    public const string PluginRpId = "vaulttype.app";

    // Windows Hello key name used for the plugin's user-verification prompts.
    public const string UserVerificationKeyName = "VaultTypePasskeyUV";
}
