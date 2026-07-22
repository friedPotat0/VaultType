using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VaultType.Models;
using VaultType.Security;
using VaultType.Vault.Crypto;

namespace VaultType.Services;

// One key the agent advertises: its SSH public-key blob and comment. Advertised even for locked
// vaults (from persisted public metadata) so a signature request can trigger an unlock.
public sealed class AgentKey
{
    public byte[] PublicBlob = Array.Empty<byte>();
    public string Comment = "";
}

// The private material resolved for a signature, after any unlock + confirmation. A null Pem means
// the request was denied (vault stayed locked, or the user declined).
public readonly record struct AgentSignMaterial(SecretBox? Pem, SecretProtector? Protector);

// A Windows OpenSSH agent: serves the vaults' SSH keys on the well-known named pipe
// \\.\pipe\openssh-ssh-agent (ssh-agent wire protocol). Supports request-identities and
// sign-request for ed25519 and RSA keys; everything else answers SSH_AGENT_FAILURE. Keys from a
// locked vault are still advertised; signing one triggers an unlock via the authorize callback.
public sealed class SshAgentService : IDisposable
{
    private const string PipeName = "openssh-ssh-agent";

    private const byte SSH_AGENT_FAILURE = 5;
    private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private const byte SSH_AGENT_IDENTITIES_ANSWER = 12;
    private const byte SSH_AGENTC_SIGN_REQUEST = 13;
    private const byte SSH_AGENT_SIGN_RESPONSE = 14;
    private const uint SSH_AGENT_RSA_SHA2_256 = 2;
    private const uint SSH_AGENT_RSA_SHA2_512 = 4;

    private readonly Func<IReadOnlyList<AgentKey>> _listKeys;
    // For a sign request: unlock the owning vault if needed, confirm if enabled, and return the
    // private key material (or an empty material to deny). Runs on a pipe thread; App marshals to UI.
    private readonly Func<byte[], string, AgentSignMaterial> _authorizeSign;
    private CancellationTokenSource? _cts;
    private Task? _listener;

    public string? LastError { get; private set; }

    public SshAgentService(Func<IReadOnlyList<AgentKey>> listKeys,
                           Func<byte[], string, AgentSignMaterial> authorizeSign)
    {
        _listKeys = listKeys;
        _authorizeSign = authorizeSign;
    }

    public bool Running => _listener is { IsCompleted: false };

    // True if something already owns the OpenSSH agent pipe (usually the built-in Windows
    // "ssh-agent" service). If so, VaultType cannot bind it and the agent won't work until that
    // service is stopped/disabled.
    public static bool PipeAlreadyOwned()
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
            client.Connect(150);
            return true;   // connected -> someone is serving the pipe
        }
        catch { return false; }
    }

    public void Start()
    {
        if (Running) return;
        _cts = new CancellationTokenSource();
        _listener = Task.Run(() => ListenAsync(_cts.Token));
    }

    public void Stop()
    {
        // Detach first so a concurrent/repeat Stop (or a fresh Start) never touches a disposed CTS.
        var cts = _cts;
        _cts = null;
        _listener = null;
        try { cts?.Cancel(); } catch { }
        try { cts?.Dispose(); } catch { }
    }

    private async Task ListenAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                // Bind the agent pipe with an explicit ACL (current user + SYSTEM only), mirroring
                // the real Windows OpenSSH agent, instead of inheriting the process default DACL.
                pipe = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    inBufferSize: 0, outBufferSize: 0,
                    pipeSecurity: CreatePipeSecurity());
            }
            catch (IOException ex)
            {
                // pipe already owned (Windows ssh-agent service running) - report once and stop
                LastError = ex.Message;
                return;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => ServeAsync(pipe, ct), ct);
            }
            catch (OperationCanceledException) { pipe.Dispose(); return; }
            catch { pipe.Dispose(); }
        }
    }

    // DACL for the agent pipe: full control for the current user (the pipe owner) and SYSTEM only,
    // so no other principal on the machine can open \\.\pipe\openssh-ssh-agent and reach the keys.
    private static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is { } user)
            security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        string client = ClientExe(pipe);
        try
        {
            var lenBuf = new byte[4];
            while (!ct.IsCancellationRequested && pipe.IsConnected)
            {
                if (!await ReadExactAsync(pipe, lenBuf, ct).ConfigureAwait(false)) return;
                int len = (int)BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
                if (len <= 0 || len > 1 << 20) return;
                var msg = new byte[len];
                if (!await ReadExactAsync(pipe, msg, ct).ConfigureAwait(false)) return;

                byte[] reply = Handle(msg, client);
                var outBuf = new byte[4 + reply.Length];
                BinaryPrimitives.WriteUInt32BigEndian(outBuf, (uint)reply.Length);
                reply.CopyTo(outBuf, 4);
                await pipe.WriteAsync(outBuf, ct).ConfigureAwait(false);
                await pipe.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch { /* client went away */ }
        finally { pipe.Dispose(); }
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(off), ct).ConfigureAwait(false);
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }

    private byte[] Handle(byte[] msg, string client)
    {
        try
        {
            return msg[0] switch
            {
                SSH_AGENTC_REQUEST_IDENTITIES => ListIdentities(),
                SSH_AGENTC_SIGN_REQUEST => Sign(msg, client),
                _ => new[] { SSH_AGENT_FAILURE },
            };
        }
        catch { return new[] { SSH_AGENT_FAILURE }; }
    }

    private byte[] ListIdentities()
    {
        var keys = _listKeys();
        var ms = new MemoryStream();
        ms.WriteByte(SSH_AGENT_IDENTITIES_ANSWER);
        WriteU32(ms, (uint)keys.Count);
        foreach (var key in keys)
        {
            WriteString(ms, key.PublicBlob);
            WriteString(ms, Encoding.UTF8.GetBytes(key.Comment));
        }
        return ms.ToArray();
    }

    private byte[] Sign(byte[] msg, string client)
    {
        int o = 1;
        byte[] blob = ReadString(msg, ref o);
        byte[] data = ReadString(msg, ref o);
        uint flags = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(o));

        // Ask the app to unlock the owning vault if needed, confirm, and hand back the private key.
        var (box, protector) = _authorizeSign(blob, client);
        if (box == null || protector == null) return new[] { SSH_AGENT_FAILURE };

        byte[] pem;
        using (var buf = protector.Reveal(box))
            pem = buf.Span.ToArray();
        try
        {
            var (alg, sig) = SshPrivateKey.Sign(pem, data, flags);
            var ms = new MemoryStream();
            ms.WriteByte(SSH_AGENT_SIGN_RESPONSE);
            var sigBlob = new MemoryStream();
            WriteString(sigBlob, Encoding.ASCII.GetBytes(alg));
            WriteString(sigBlob, sig);
            WriteString(ms, sigBlob.ToArray());
            return ms.ToArray();
        }
        catch
        {
            return new[] { SSH_AGENT_FAILURE };
        }
        finally { CryptographicOperations.ZeroMemory(pem); }
    }

    // The raw SSH public-key blob ("ssh-ed25519 <base64> comment" -> the decoded base64).
    public static byte[] PublicKeyToBlob(string publicKeyLine)
    {
        var parts = publicKeyLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        try { return parts.Length >= 2 ? Convert.FromBase64String(parts[1]) : Array.Empty<byte>(); }
        catch { return Array.Empty<byte>(); }
    }

    private static string ClientExe(NamedPipeServerStream pipe)
    {
        try
        {
            if (GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
                return System.Diagnostics.Process.GetProcessById((int)pid).ProcessName + ".exe";
        }
        catch { }
        return "?";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    // ---- wire helpers ----
    private static void WriteU32(Stream s, uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        s.Write(b);
    }

    private static void WriteString(Stream s, byte[] data)
    {
        WriteU32(s, (uint)data.Length);
        s.Write(data, 0, data.Length);
    }

    private static byte[] ReadString(byte[] buf, ref int o)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(o));
        o += 4;
        var r = buf.AsSpan(o, (int)len).ToArray();
        o += (int)len;
        return r;
    }

    public void Dispose() => Stop();
}

// Parses an (unencrypted) OpenSSH private key PEM and signs agent requests.
// ed25519 signs via our own managed Ed25519 (Vault/Crypto); RSA via .NET RSA with the PKCS#1 parts.
internal static class SshPrivateKey
{
    public static (string Alg, byte[] Sig) Sign(byte[] pem, byte[] data, uint flags)
    {
        byte[] blob = DecodePem(pem);
        byte[]? priv = null;
        try
        {
            // openssh-key-v1 layout
            int o = 0;
            string magic = "openssh-key-v1\0";
            if (!blob.AsSpan(0, magic.Length).SequenceEqual(Encoding.ASCII.GetBytes(magic)))
                throw new CryptographicException("Not an OpenSSH private key.");
            o += magic.Length;
            string cipher = Str(blob, ref o);
            _ = Str(blob, ref o);                       // kdfname
            _ = Bytes(blob, ref o);                     // kdfoptions
            if (cipher != "none") throw new CryptographicException("Passphrase-protected SSH keys are not supported.");
            uint nkeys = U32(blob, ref o);
            if (nkeys != 1) throw new CryptographicException("Multi-key OpenSSH files are not supported.");
            _ = Bytes(blob, ref o);                     // public key blob
            priv = Bytes(blob, ref o);                  // private section (plaintext, cipher none)

            int p = 8;                                  // skip checkint x2
            string keyType = Str(priv, ref p);
            switch (keyType)
            {
                case "ssh-ed25519":
                {
                    _ = Bytes(priv, ref p);             // public
                    byte[] sk = Bytes(priv, ref p);     // 64 bytes: seed(32) || public(32)
                    try
                    {
                        if (sk.Length < 32) throw new CryptographicException("ed25519 private key too short");
                        return ("ssh-ed25519", Ed25519.Sign(sk.AsSpan(0, 32), data));
                    }
                    finally { CryptographicOperations.ZeroMemory(sk); }
                }
                case "ssh-rsa":
                {
                    byte[] n = Bytes(priv, ref p);
                    byte[] e = Bytes(priv, ref p);
                    byte[] d = Bytes(priv, ref p);
                    byte[] iqmp = Bytes(priv, ref p);   // iqmp (derived from the private factors)
                    byte[] pq = Bytes(priv, ref p);
                    byte[] q = Bytes(priv, ref p);
                    RSAParameters rp = default;
                    try
                    {
                        rp = RsaParams(n, e, d, pq, q);
                        using var rsa = RSA.Create();
                        rsa.ImportParameters(rp);
                        (string alg, HashAlgorithmName hash) = (flags & 4) != 0 ? ("rsa-sha2-512", HashAlgorithmName.SHA512)
                            : (flags & 2) != 0 ? ("rsa-sha2-256", HashAlgorithmName.SHA256)
                            : ("ssh-rsa", HashAlgorithmName.SHA1);
                        return (alg, rsa.SignData(data, hash, RSASignaturePadding.Pkcs1));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(n);
                        CryptographicOperations.ZeroMemory(e);
                        CryptographicOperations.ZeroMemory(d);
                        CryptographicOperations.ZeroMemory(iqmp);
                        CryptographicOperations.ZeroMemory(pq);
                        CryptographicOperations.ZeroMemory(q);
                        ZeroRsaParameters(ref rp);
                    }
                }
                default:
                    throw new CryptographicException($"Unsupported SSH key type '{keyType}'.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
            if (priv != null) CryptographicOperations.ZeroMemory(priv);
        }
    }

    // Wipes the secret CRT components of the parameters produced by RsaParams once they have been
    // imported. Modulus/Exponent are public, so they are left as-is. Note: the BigInteger values in
    // RsaParams/ModInverse/Egcd keep their own internal arrays, which the managed BigInteger type
    // gives no way to zero - an unavoidable residual for the RSA path.
    private static void ZeroRsaParameters(ref RSAParameters rp)
    {
        if (rp.D is { } d) CryptographicOperations.ZeroMemory(d);
        if (rp.P is { } p) CryptographicOperations.ZeroMemory(p);
        if (rp.Q is { } q) CryptographicOperations.ZeroMemory(q);
        if (rp.DP is { } dp) CryptographicOperations.ZeroMemory(dp);
        if (rp.DQ is { } dq) CryptographicOperations.ZeroMemory(dq);
        if (rp.InverseQ is { } iq) CryptographicOperations.ZeroMemory(iq);
    }

    private static RSAParameters RsaParams(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q)
    {
        static byte[] Trim(byte[] b) { int i = 0; while (i < b.Length - 1 && b[i] == 0) i++; return b[i..]; }
        var N = new System.Numerics.BigInteger(Trim(n), isUnsigned: true, isBigEndian: true);
        var D = new System.Numerics.BigInteger(Trim(d), isUnsigned: true, isBigEndian: true);
        var P = new System.Numerics.BigInteger(Trim(p), isUnsigned: true, isBigEndian: true);
        var Q = new System.Numerics.BigInteger(Trim(q), isUnsigned: true, isBigEndian: true);
        var dp = D % (P - 1);
        var dq = D % (Q - 1);
        var qinv = ModInverse(Q, P);
        int half = (Trim(n).Length + 1) / 2;
        return new RSAParameters
        {
            Modulus = Trim(n), Exponent = Trim(e), D = Export(D, Trim(n).Length),
            P = Export(P, half), Q = Export(Q, half),
            DP = Export(dp, half), DQ = Export(dq, half), InverseQ = Export(qinv, half),
        };
    }

    private static System.Numerics.BigInteger ModInverse(System.Numerics.BigInteger a, System.Numerics.BigInteger m)
        => System.Numerics.BigInteger.ModPow(a, m - 2, m) is var r && (r * a) % m == 1 ? r : Egcd(a, m);

    private static System.Numerics.BigInteger Egcd(System.Numerics.BigInteger a, System.Numerics.BigInteger m)
    {
        System.Numerics.BigInteger g = m, x = 0, x1 = 1, a1 = a;
        while (a1 != 0)
        {
            var qd = System.Numerics.BigInteger.DivRem(g, a1, out var r);
            (g, a1) = (a1, r);
            (x, x1) = (x1, x - qd * x1);
        }
        return ((x % m) + m) % m;
    }

    private static byte[] Export(System.Numerics.BigInteger v, int length)
    {
        byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == length) return raw;
        var outp = new byte[length];
        raw.CopyTo(outp, length - raw.Length);
        return outp;
    }

    // Decodes the base64 body of an unencrypted OpenSSH private-key PEM straight from the ASCII byte
    // span. Deliberately avoids Encoding.GetString / the base64 string: managed strings holding key
    // material cannot be wiped. The scratch buffers here do hold key material and are zeroed.
    private static byte[] DecodePem(byte[] pem)
    {
        ReadOnlySpan<byte> head = "-----BEGIN OPENSSH PRIVATE KEY-----"u8;
        ReadOnlySpan<byte> tail = "-----END OPENSSH PRIVATE KEY-----"u8;
        ReadOnlySpan<byte> span = pem;
        int i = span.IndexOf(head);
        int j = span.IndexOf(tail);
        if (i < 0 || j < 0) throw new CryptographicException("Not an OpenSSH private key PEM.");
        ReadOnlySpan<byte> body = span[(i + head.Length)..j];

        // Pack the base64 payload without its line breaks / whitespace, then decode in place.
        byte[] packed = new byte[body.Length];
        try
        {
            int n = 0;
            foreach (byte b in body)
                if (b is not ((byte)'\r' or (byte)'\n' or (byte)' ' or (byte)'\t'))
                    packed[n++] = b;

            byte[] outp = new byte[Base64.GetMaxDecodedFromUtf8Length(n)];
            OperationStatus status = Base64.DecodeFromUtf8(packed.AsSpan(0, n), outp, out _, out int written);
            if (status != OperationStatus.Done)
            {
                CryptographicOperations.ZeroMemory(outp);
                throw new CryptographicException("Invalid OpenSSH private key base64.");
            }
            if (written == outp.Length) return outp;
            byte[] trimmed = outp.AsSpan(0, written).ToArray();
            CryptographicOperations.ZeroMemory(outp);
            return trimmed;
        }
        finally { CryptographicOperations.ZeroMemory(packed); }
    }

    private static uint U32(byte[] b, ref int o)
    {
        uint v = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o));
        o += 4;
        return v;
    }

    private static byte[] Bytes(byte[] b, ref int o)
    {
        uint len = U32(b, ref o);
        var r = b.AsSpan(o, (int)len).ToArray();
        o += (int)len;
        return r;
    }

    private static string Str(byte[] b, ref int o) => Encoding.ASCII.GetString(Bytes(b, ref o));
}
