using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace VaultType.Security;

// We hand the master password to bw.exe, so we only run one we can attribute to Bitwarden:
// a valid Authenticode chain plus a signer whose subject is Bitwarden. Chain validation is
// offline (no revocation lookups) so this never makes a silent network call.
internal static class CodeSignature
{
    public static bool IsBitwardenTrusted(string path)
        => File.Exists(path) && ChainTrusted(path) && SignedByBitwarden(path);

    private static bool ChainTrusted(string path)
    {
        var file = new Native.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        IntPtr pFile = Marshal.AllocHGlobal((int)file.cbStruct);
        IntPtr pData = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(file, pFile, false);
            var data = new Native.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
                dwUIChoice = Native.WTD_UI_NONE,
                fdwRevocationChecks = Native.WTD_REVOKE_NONE,
                dwUnionChoice = Native.WTD_CHOICE_FILE,
                pFile = pFile,
                dwProvFlags = Native.WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwStateAction = Native.WTD_STATEACTION_VERIFY,
            };
            pData = Marshal.AllocHGlobal((int)data.cbStruct);
            Marshal.StructureToPtr(data, pData, false);

            int rc = Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            // release the state the verify call allocated, whatever the outcome
            data = Marshal.PtrToStructure<Native.WINTRUST_DATA>(pData);
            data.dwStateAction = Native.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, false);
            Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return rc == 0;   // 0 = signed and the chain terminates in a trusted root
        }
        catch { return false; }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            Marshal.DestroyStructure<Native.WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    // OIDs of the RDNs we pin.
    private const string OidOrganization = "2.5.4.10";
    private const string OidCommonName = "2.5.4.3";
    private const string BitwardenName = "Bitwarden Inc.";

    private static bool SignedByBitwarden(string path)
    {
        try
        {
            // No non-obsolete API extracts the Authenticode signer cert from a PE - X509CertificateLoader
            // only reads plain certificate files. The chain itself was already validated above.
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057

            // Pin the CA-verified organisation identity, not a loose substring: both the organisation
            // and the common name must be exactly Bitwarden's. This survives certificate renewals
            // (the legal name is stable) while a thumbprint pin would reject every renewed bw.exe.
            string? org = null, cn = null;
            foreach (var rdn in new X500DistinguishedName(cert.Subject).EnumerateRelativeDistinguishedNames())
            {
                string oid = rdn.GetSingleElementType().Value ?? "";
                if (oid == OidOrganization) org = rdn.GetSingleElementValue();
                else if (oid == OidCommonName) cn = rdn.GetSingleElementValue();
            }
            return string.Equals(org, BitwardenName, StringComparison.Ordinal)
                && string.Equals(cn, BitwardenName, StringComparison.Ordinal);
        }
        catch { return false; }
    }
}
