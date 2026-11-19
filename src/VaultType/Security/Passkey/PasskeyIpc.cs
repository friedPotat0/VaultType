using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace VaultType.Security.Passkey;

// IPC between the short-lived plugin COM process and the running tray instance, which holds the
// unlocked vault and owns the UI. One request per connection: 4-byte little-endian length + UTF-8
// JSON in each direction. The pipe is per-user; the default pipe ACL restricts it to that user.
//
// Binary fields travel base64-encoded. No secret ever crosses the pipe - signatures are computed
// on the tray side, where the private keys live.

internal sealed class PasskeyIpcRequest
{
    public string Op { get; set; } = "";          // "status" | "getAssertion" | "makeCredential"
    public string RpId { get; set; } = "";
    public string? RpName { get; set; }
    public string? ClientDataHash { get; set; }    // b64
    public List<string> CredentialIds { get; set; } = new();   // b64; allowList or excludeList
    public string? UserId { get; set; }            // b64 (makeCredential)
    public string? UserName { get; set; }
    public string? UserDisplayName { get; set; }
    public bool Discoverable { get; set; }
    public bool UserVerified { get; set; }         // Hello UV already performed by the plugin process
}

internal sealed class PasskeyIpcResponse
{
    public bool Ok { get; set; }
    public byte Status { get; set; } = (byte)CtapStatus.OtherError;   // CTAP status when !Ok
    public bool Unlocked { get; set; }             // "status" op

    public string? CredentialId { get; set; }      // b64
    public string? AuthData { get; set; }          // b64
    public string? Signature { get; set; }         // b64 (getAssertion)
    public string? UserHandle { get; set; }        // b64
    public string? UserName { get; set; }
    public string? UserDisplayName { get; set; }
    public int Count { get; set; }

    public static PasskeyIpcResponse Fail(CtapStatus status) => new() { Ok = false, Status = (byte)status };
}

internal static class PasskeyIpc
{
    internal static string PipeName => $"VaultType.passkey.{Environment.UserName}";

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    internal static void WriteMessage<T>(Stream s, T message)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        Span<byte> len = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(len, payload.Length);
        s.Write(len);
        s.Write(payload);
        s.Flush();
    }

    internal static T? ReadMessage<T>(Stream s)
    {
        Span<byte> len = stackalloc byte[4];
        if (!FillBuffer(s, len)) return default;
        int size = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(len);
        if (size <= 0 || size > 1 << 20) return default;
        byte[] payload = new byte[size];
        if (!FillBuffer(s, payload)) return default;
        return JsonSerializer.Deserialize<T>(payload, Json);
    }

    private static bool FillBuffer(Stream s, Span<byte> buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = s.Read(buffer[read..]);
            if (n <= 0) return false;
            read += n;
        }
        return true;
    }
}

// Tray-side server. Start()/Stop() mirror SshAgentService; the handler runs on a worker thread and
// may block on UI (the App marshals to the Dispatcher itself, exactly like the SSH sign path).
internal sealed class PasskeyIpcServer : IDisposable
{
    private readonly Func<PasskeyIpcRequest, PasskeyIpcResponse> _handler;
    private CancellationTokenSource? _cts;

    // The plugin sends its request immediately after connecting; a peer that connects but then sits
    // silent must not pin a worker thread. Only bounds the handshake, not the handler (which may
    // legitimately wait on the tray's unlock/confirmation window).
    private const int HandshakeTimeoutMs = 10_000;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle Pipe, out uint ClientProcessId);

    internal PasskeyIpcServer(Func<PasskeyIpcRequest, PasskeyIpcResponse> handler) => _handler = handler;

    internal void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        Task.Run(() => AcceptLoop(ct), ct);
    }

    internal void Stop()
    {
        _cts?.Cancel();
        _cts = null;
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                // Explicit DACL: only the current user may touch the pipe, rather than relying on
                // the default descriptor. Defence in depth behind the per-user pipe name and the
                // peer check in Serve.
                var server = NamedPipeServerStreamAcl.Create(
                    PasskeyIpc.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    inBufferSize: 0, outBufferSize: 0, CreatePipeSecurity());
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => Serve(server), ct);
            }
            catch (OperationCanceledException) { break; }
            catch
            {
                try { await Task.Delay(500, ct).ConfigureAwait(false); } catch { break; }
            }
        }
    }

    private void Serve(NamedPipeServerStream pipe)
    {
        using (pipe)
        {
            try
            {
                // The request carries the UserVerified flag and drives signing, so only answer the
                // genuine plugin process - never an arbitrary same-session process talking to the
                // pipe directly (which would bypass the Windows operation-signature check the plugin
                // performs before it ever forwards a request here).
                if (!IsTrustedClient(pipe)) return;

                // Read the request under a timeout so a client that connects but never sends can't
                // pin this worker thread; disposing the pipe unblocks the stuck read.
                PasskeyIpcRequest? request;
                using (var handshake = new CancellationTokenSource(HandshakeTimeoutMs))
                using (handshake.Token.Register(static state => { try { ((IDisposable)state!).Dispose(); } catch { } }, pipe))
                {
                    request = PasskeyIpc.ReadMessage<PasskeyIpcRequest>(pipe);
                }
                if (request == null) return;
                PasskeyIpcResponse response;
                try { response = _handler(request); }
                catch
                {
                    response = PasskeyIpcResponse.Fail(CtapStatus.OtherError);
                }
                PasskeyIpc.WriteMessage(pipe, response);
            }
            catch { }
        }
    }

    private static PipeSecurity CreatePipeSecurity()
    {
        var sec = new PipeSecurity();
        var user = WindowsIdentity.GetCurrent().User!;
        sec.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        return sec;
    }

    // Only the plugin process may talk to this pipe. Windows always starts it ("-PluginActivated")
    // from the installed MSIX package, while the tray answering here may be another build: the
    // installer or portable edition, a development build, or an older package version still running
    // after the Store updated VaultType. So the peer is accepted when it is either this very
    // executable or any process of VaultType's own package. Package identity is assigned by Windows
    // at launch and can't be taken on by an ordinary process. Fail closed otherwise.
    private static bool IsTrustedClient(NamedPipeServerStream pipe)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid))
                return false;

            string? self = Environment.ProcessPath;
            string? client = null;
            try { using var p = Process.GetProcessById((int)pid); client = p.MainModule?.FileName; }
            catch { }
            if (self != null && client != null && string.Equals(self, client, StringComparison.OrdinalIgnoreCase))
                return true;

            string? family = PackageFamilyOf(pid);
            return family != null && TrustedPackageFamilies.Value.Contains(family);
        }
        catch
        {
            return false;
        }
    }

    private static readonly Lazy<HashSet<string>> TrustedPackageFamilies = new(() =>
        PasskeyIds.PackageIdentities
            .Select(id => FamilyNameFromId(id.Name, id.Publisher))
            .Where(f => f != null)
            .Select(f => f!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase));

    // Null for a process without package identity (APPMODEL_ERROR_NO_PACKAGE) or one we can't open.
    private static string? PackageFamilyOf(uint pid)
    {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            uint length = 256;
            var name = new System.Text.StringBuilder((int)length);
            return GetPackageFamilyName(process, ref length, name) == 0 ? name.ToString() : null;
        }
        finally { CloseHandle(process); }
    }

    // Name + publisher -> "Name_publisherId", computed by Windows itself.
    private static string? FamilyNameFromId(string name, string publisher)
    {
        var id = new PackageId { Name = name, Publisher = publisher };
        uint length = 256;
        var family = new System.Text.StringBuilder((int)length);
        return PackageFamilyNameFromId(ref id, ref length, family) == 0 ? family.ToString() : null;
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PackageId
    {
        public uint Reserved;
        public uint ProcessorArchitecture;
        public ulong Version;
        public string Name;
        public string Publisher;
        public string? ResourceId;
        public string? PublisherId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int PackageFamilyNameFromId(ref PackageId packageId, ref uint packageFamilyNameLength,
        System.Text.StringBuilder packageFamilyName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackageFamilyName(IntPtr hProcess, ref uint packageFamilyNameLength,
        System.Text.StringBuilder packageFamilyName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public void Dispose() => Stop();
}
