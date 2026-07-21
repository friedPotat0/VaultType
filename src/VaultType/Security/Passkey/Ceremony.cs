using System.Runtime.InteropServices;
using VaultType.Config;

namespace VaultType.Security.Passkey;

// Runs a passkey ceremony on behalf of PluginAuthenticator.
//
// Process model: Windows activates "VaultType.exe -PluginActivated" as a COM server, so this code
// runs in its OWN process - not in the tray instance the user already unlocked. The ceremony
// decodes the CTAP request, performs Windows Hello user verification here (this process is the
// registered plugin, so the UV key belongs to it), then forwards the semantic request over the
// PasskeyBridge pipe to the tray instance, which owns the vault keys, does the signing and any
// unlock/confirmation UI. The CTAP response is encoded back here.
internal static class Ceremony
{
    private static readonly HashSet<Guid> CancelledTransactions = new();
    private static readonly object Gate = new();

    internal static void Cancel(Guid transactionId)
    {
        lock (Gate)
        {
            // Bounded: the process is short-lived, but never let a flood of cancels grow without limit.
            if (CancelledTransactions.Count > 1024) CancelledTransactions.Clear();
            CancelledTransactions.Add(transactionId);
        }
    }

    private static bool IsCancelled(Guid transactionId)
    {
        lock (Gate) return CancelledTransactions.Contains(transactionId);
    }

    internal static bool VaultUnlocked() => PasskeyBridge.VaultUnlocked();

    internal static byte[] MakeCredential(Guid transactionId, IntPtr hwnd, ReadOnlyMemory<byte> encodedRequest)
    {
        CtapMakeCredentialRequest req;
        try { req = Ctap2.DecodeMakeCredential(encodedRequest); }
        catch (CtapException ex) { PasskeyLog.Write($"MakeCredential: {ex.Message}"); return Ctap2.Error(ex.Status); }

        PasskeyLog.Write($"MakeCredential rp={PasskeyLog.Redact(req.RpId)} user={PasskeyLog.Redact(req.UserName)} rk={req.RequireResidentKey} uv={req.RequireUserVerification}");

        var (uvWanted, userVerified) = PerformUserVerification(transactionId, hwnd, req.RequireUserVerification, req.UserName);
        if (uvWanted && !userVerified) return Ctap2.Error(CtapStatus.OperationDenied);
        if (IsCancelled(transactionId)) return Ctap2.Error(CtapStatus.KeepAliveCancel);

        var resp = PasskeyBridge.Send(new PasskeyIpcRequest
        {
            Op = "makeCredential",
            RpId = req.RpId,
            RpName = req.RpName,
            ClientDataHash = Convert.ToBase64String(req.ClientDataHash),
            CredentialIds = req.ExcludeList.Select(c => Convert.ToBase64String(c.Id)).ToList(),
            UserId = Convert.ToBase64String(req.UserId),
            UserName = req.UserName,
            UserDisplayName = req.UserDisplayName,
            Discoverable = req.RequireResidentKey,
            UserVerified = userVerified,
        });
        if (!resp.Ok || resp.AuthData == null) return Ctap2.Error((CtapStatus)resp.Status);
        if (IsCancelled(transactionId)) return Ctap2.Error(CtapStatus.KeepAliveCancel);

        return Ctap2.EncodeMakeCredentialResponse(Convert.FromBase64String(resp.AuthData));
    }

    internal static byte[] GetAssertion(Guid transactionId, IntPtr hwnd, ReadOnlyMemory<byte> encodedRequest)
    {
        CtapGetAssertionRequest req;
        try { req = Ctap2.DecodeGetAssertion(encodedRequest); }
        catch (CtapException ex) { PasskeyLog.Write($"GetAssertion: {ex.Message}"); return Ctap2.Error(ex.Status); }

        PasskeyLog.Write($"GetAssertion rp={PasskeyLog.Redact(req.RpId)} allowList={req.AllowList.Count} uv={req.RequireUserVerification}");

        var (uvWanted, userVerified) = PerformUserVerification(transactionId, hwnd, req.RequireUserVerification, req.RpId);
        if (uvWanted && !userVerified) return Ctap2.Error(CtapStatus.OperationDenied);
        if (IsCancelled(transactionId)) return Ctap2.Error(CtapStatus.KeepAliveCancel);

        var resp = PasskeyBridge.Send(new PasskeyIpcRequest
        {
            Op = "getAssertion",
            RpId = req.RpId,
            ClientDataHash = Convert.ToBase64String(req.ClientDataHash),
            CredentialIds = req.AllowList.Select(c => Convert.ToBase64String(c.Id)).ToList(),
            UserVerified = userVerified,
        });
        if (!resp.Ok || resp.CredentialId == null || resp.AuthData == null || resp.Signature == null)
            return Ctap2.Error((CtapStatus)resp.Status);
        if (IsCancelled(transactionId)) return Ctap2.Error(CtapStatus.KeepAliveCancel);

        return Ctap2.EncodeGetAssertionResponse(
            Convert.FromBase64String(resp.CredentialId),
            Convert.FromBase64String(resp.AuthData),
            Convert.FromBase64String(resp.Signature),
            resp.UserHandle != null ? Convert.FromBase64String(resp.UserHandle) : Array.Empty<byte>(),
            resp.UserName, resp.UserDisplayName, Math.Max(1, resp.Count));
    }

    // Windows Hello prompt via the plugin UV API. Runs when the relying party asked for user
    // verification or the "require Windows Hello" setting is on. Returns (Wanted, Verified): when UV
    // was wanted (by the RP OR the setting) but did not succeed, the caller rejects the ceremony -
    // so "require Windows Hello" is a hard gate, not merely advisory.
    private static (bool Wanted, bool Verified) PerformUserVerification(Guid transactionId, IntPtr hwnd, bool requested, string? userName)
    {
        bool wanted = requested;
        try { wanted |= AppConfig.Load().PasskeyRequireHello; }
        catch { }
        if (!wanted) return (false, false);

        IntPtr pGuid = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        IntPtr response = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(transactionId, pGuid, fDeleteOld: false);
            // v1 API, all strings non-null - matching the official sample; null strings fail with
            // E_POINTER. The username is shown in the Hello prompt, so fall back to the RP context.
            var uvRequest = new PluginUserVerificationRequest
            {
                Hwnd = hwnd,
                PGuidTransactionId = pGuid,
                Username = string.IsNullOrEmpty(userName) ? PasskeyIds.AuthenticatorName : userName,
                DisplayHint = PasskeyIds.AuthenticatorName,
            };
            int hr = PasskeyNative.WebAuthNPluginPerformUserVerification(ref uvRequest, out _, out response);
            PasskeyLog.Write($"uv: hr=0x{hr:X8}");
            return (true, hr == PasskeyNative.S_OK);
        }
        catch (Exception ex)
        {
            PasskeyLog.Write($"uv: failed: {ex.Message}");
            return (true, false);
        }
        finally
        {
            if (response != IntPtr.Zero) PasskeyNative.WebAuthNPluginFreeUserVerificationResponse(response);
            Marshal.FreeHGlobal(pGuid);
        }
    }
}
