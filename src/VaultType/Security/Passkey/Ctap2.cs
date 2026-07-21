using System.Formats.Cbor;
using System.IO;
using System.Security.Cryptography;

namespace VaultType.Security.Passkey;

// CTAP2 message encoding. Windows hands the plugin raw CTAP2 CBOR and expects CTAP2 CBOR back, so
// this is the wire format of the whole feature. Field numbers follow the FIDO Client to
// Authenticator Protocol (CTAP) 2.1 specification.
internal static class Ctap2
{
    // COSE algorithm identifiers (RFC 9053). Passkeys in the Bitwarden vault are ES256.
    internal const int CoseEs256 = -7;

    // Authenticator data flags (WebAuthn §6.1).
    internal const byte FlagUserPresent = 0x01;
    internal const byte FlagUserVerified = 0x04;
    internal const byte FlagBackupEligible = 0x08;
    internal const byte FlagBackedUp = 0x10;
    internal const byte FlagAttestedCredentialData = 0x40;

    // --- authenticatorGetInfo (0x04) ---------------------------------------------------------
    // Describes this authenticator to Windows at registration time. Returned as the response map
    // only; the status byte is not part of what WebAuthNPluginAddAuthenticator expects.
    internal static byte[] BuildAuthenticatorInfo()
    {
        var w = new CborWriter(CborConformanceMode.Ctap2Canonical);
        w.WriteStartMap(6);

        w.WriteInt32(0x01);                       // versions
        w.WriteStartArray(2);
        w.WriteTextString("FIDO_2_0");
        w.WriteTextString("FIDO_2_1");
        w.WriteEndArray();

        w.WriteInt32(0x03);                       // aaguid
        w.WriteByteString(PasskeyIds.AaguidBytes);

        w.WriteInt32(0x04);                       // options
        w.WriteStartMap(4);
        w.WriteTextString("plat"); w.WriteBoolean(true);    // platform authenticator, not removable
        w.WriteTextString("rk"); w.WriteBoolean(true);      // discoverable credentials
        w.WriteTextString("up"); w.WriteBoolean(true);      // user presence
        w.WriteTextString("uv"); w.WriteBoolean(true);      // user verification (Windows Hello)
        w.WriteEndMap();

        w.WriteInt32(0x05);                       // maxMsgSize
        w.WriteInt32(2048);

        w.WriteInt32(0x09);                       // transports
        w.WriteStartArray(1);
        w.WriteTextString("internal");
        w.WriteEndArray();

        w.WriteInt32(0x0A);                       // algorithms
        w.WriteStartArray(1);
        w.WriteStartMap(2);
        w.WriteTextString("alg"); w.WriteInt32(CoseEs256);
        w.WriteTextString("type"); w.WriteTextString("public-key");
        w.WriteEndMap();
        w.WriteEndArray();

        w.WriteEndMap();
        return w.Encode();
    }

    // --- request decoding --------------------------------------------------------------------

    // A CTAP2 message may or may not be prefixed with its command byte. A CBOR map starts at 0xA0,
    // so anything below that is a command byte to skip.
    private static CborReader OpenRequest(ReadOnlyMemory<byte> encoded)
    {
        if (encoded.Length == 0) throw new CtapException(CtapStatus.InvalidCbor, "empty request");
        if (encoded.Span[0] < 0xA0) encoded = encoded[1..];
        return new CborReader(encoded, CborConformanceMode.Lax);
    }

    internal static CtapMakeCredentialRequest DecodeMakeCredential(ReadOnlyMemory<byte> encoded)
    {
        var r = OpenRequest(encoded);
        byte[] clientDataHash = Array.Empty<byte>();
        string rpId = "", rpName = "";
        byte[] userId = Array.Empty<byte>();
        string userName = "", userDisplay = "";
        var algs = new List<int>();
        var exclude = new List<CtapCredentialDescriptor>();
        bool rk = false, uv = false;

        foreach (int key in ReadMapKeys(r))
        {
            switch (key)
            {
                case 0x01: clientDataHash = r.ReadByteString(); break;
                case 0x02: (rpId, rpName) = ReadEntity(r); break;
                case 0x03: (userId, userName, userDisplay) = ReadUser(r); break;
                case 0x04: algs.AddRange(ReadAlgorithms(r)); break;
                case 0x05: exclude.AddRange(ReadCredentialList(r)); break;
                case 0x07: (rk, uv) = ReadOptions(r); break;
                default: r.SkipValue(); break;
            }
        }

        if (clientDataHash.Length == 0) throw new CtapException(CtapStatus.MissingParameter, "clientDataHash");
        if (rpId.Length == 0) throw new CtapException(CtapStatus.MissingParameter, "rp.id");
        // A discoverable (resident) credential must carry a non-empty user.id (CTAP2 §5.1) - a blank
        // handle could never be resolved in a username-less flow. Reject rather than store it empty.
        if (rk && userId.Length == 0) throw new CtapException(CtapStatus.MissingParameter, "user.id");
        if (algs.Count > 0 && !algs.Contains(CoseEs256))
            throw new CtapException(CtapStatus.UnsupportedAlgorithm, "only ES256 is supported");

        return new CtapMakeCredentialRequest
        {
            ClientDataHash = clientDataHash,
            RpId = rpId,
            RpName = rpName,
            UserId = userId,
            UserName = userName,
            UserDisplayName = userDisplay,
            Algorithms = algs,
            ExcludeList = exclude,
            RequireResidentKey = rk,
            RequireUserVerification = uv,
        };
    }

    internal static CtapGetAssertionRequest DecodeGetAssertion(ReadOnlyMemory<byte> encoded)
    {
        var r = OpenRequest(encoded);
        string rpId = "";
        byte[] clientDataHash = Array.Empty<byte>();
        var allow = new List<CtapCredentialDescriptor>();
        bool up = true, uv = false;

        foreach (int key in ReadMapKeys(r))
        {
            switch (key)
            {
                case 0x01: rpId = r.ReadTextString(); break;
                case 0x02: clientDataHash = r.ReadByteString(); break;
                case 0x03: allow.AddRange(ReadCredentialList(r)); break;
                case 0x05: (up, uv) = ReadAssertionOptions(r); break;
                default: r.SkipValue(); break;
            }
        }

        if (rpId.Length == 0) throw new CtapException(CtapStatus.MissingParameter, "rpId");
        if (clientDataHash.Length == 0) throw new CtapException(CtapStatus.MissingParameter, "clientDataHash");

        return new CtapGetAssertionRequest
        {
            RpId = rpId,
            ClientDataHash = clientDataHash,
            AllowList = allow,
            // "up" is captured for completeness. We do not honour a silent (up=false) request: the
            // tray always requires presence via its Hello/confirmation UI before signing, so every
            // assertion is user-present and the FlagUserPresent bit is always set.
            RequireUserPresence = up,
            RequireUserVerification = uv,
        };
    }

    // Yields each integer key of the top-level map, leaving the reader positioned on its value.
    private static IEnumerable<int> ReadMapKeys(CborReader r)
    {
        int? count;
        try { count = r.ReadStartMap(); }
        catch (CborContentException ex) { throw new CtapException(CtapStatus.InvalidCbor, ex.Message); }

        for (int i = 0; count == null ? r.PeekState() != CborReaderState.EndMap : i < count; i++)
        {
            int key;
            try { key = r.ReadInt32(); }
            catch (Exception ex) when (ex is CborContentException or InvalidOperationException or OverflowException)
            { throw new CtapException(CtapStatus.CborUnexpectedType, "map key must be an integer"); }
            yield return key;
        }
        r.ReadEndMap();
    }

    // {"id": "example.com", "name": "Example"}
    private static (string Id, string Name) ReadEntity(CborReader r)
    {
        string id = "", name = "";
        int? count = r.ReadStartMap();
        for (int i = 0; count == null ? r.PeekState() != CborReaderState.EndMap : i < count; i++)
        {
            switch (r.ReadTextString())
            {
                case "id": id = r.ReadTextString(); break;
                case "name": name = r.ReadTextString(); break;
                default: r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return (id, name);
    }

    private static (byte[] Id, string Name, string DisplayName) ReadUser(CborReader r)
    {
        byte[] id = Array.Empty<byte>();
        string name = "", display = "";
        int? count = r.ReadStartMap();
        for (int i = 0; count == null ? r.PeekState() != CborReaderState.EndMap : i < count; i++)
        {
            switch (r.ReadTextString())
            {
                case "id": id = r.ReadByteString(); break;
                case "name": name = r.ReadTextString(); break;
                case "displayName": display = r.ReadTextString(); break;
                default: r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return (id, name, display);
    }

    // [{"alg": -7, "type": "public-key"}, ...]
    private static List<int> ReadAlgorithms(CborReader r)
    {
        var algs = new List<int>();
        int? n = r.ReadStartArray();
        for (int i = 0; n == null ? r.PeekState() != CborReaderState.EndArray : i < n; i++)
        {
            int? m = r.ReadStartMap();
            for (int j = 0; m == null ? r.PeekState() != CborReaderState.EndMap : j < m; j++)
            {
                if (r.ReadTextString() == "alg") algs.Add(r.ReadInt32());
                else r.SkipValue();
            }
            r.ReadEndMap();
        }
        r.ReadEndArray();
        return algs;
    }

    // [{"id": h'..', "type": "public-key"}, ...]
    private static List<CtapCredentialDescriptor> ReadCredentialList(CborReader r)
    {
        var list = new List<CtapCredentialDescriptor>();
        int? n = r.ReadStartArray();
        for (int i = 0; n == null ? r.PeekState() != CborReaderState.EndArray : i < n; i++)
        {
            byte[] id = Array.Empty<byte>();
            string type = "public-key";
            int? m = r.ReadStartMap();
            for (int j = 0; m == null ? r.PeekState() != CborReaderState.EndMap : j < m; j++)
            {
                switch (r.ReadTextString())
                {
                    case "id": id = r.ReadByteString(); break;
                    case "type": type = r.ReadTextString(); break;
                    default: r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
            list.Add(new CtapCredentialDescriptor { Id = id, Type = type });
        }
        r.ReadEndArray();
        return list;
    }

    private static (bool Rk, bool Uv) ReadOptions(CborReader r)
    {
        bool rk = false, uv = false;
        int? count = r.ReadStartMap();
        for (int i = 0; count == null ? r.PeekState() != CborReaderState.EndMap : i < count; i++)
        {
            switch (r.ReadTextString())
            {
                case "rk": rk = r.ReadBoolean(); break;
                case "uv": uv = r.ReadBoolean(); break;
                default: r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return (rk, uv);
    }

    private static (bool Up, bool Uv) ReadAssertionOptions(CborReader r)
    {
        bool up = true, uv = false;
        int? count = r.ReadStartMap();
        for (int i = 0; count == null ? r.PeekState() != CborReaderState.EndMap : i < count; i++)
        {
            switch (r.ReadTextString())
            {
                case "up": up = r.ReadBoolean(); break;
                case "uv": uv = r.ReadBoolean(); break;
                default: r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return (up, uv);
    }

    // --- authenticator data ------------------------------------------------------------------

    // rpIdHash(32) | flags(1) | signCount(4, big endian) | [attestedCredentialData]
    internal static byte[] BuildAuthenticatorData(string rpId, byte flags, uint signCount,
                                                  byte[]? credentialId = null, byte[]? cosePublicKey = null)
    {
        using var ms = new MemoryStream();
        ms.Write(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rpId)));
        ms.WriteByte(flags);
        Span<byte> counter = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(counter, signCount);
        ms.Write(counter);

        if ((flags & FlagAttestedCredentialData) != 0)
        {
            ArgumentNullException.ThrowIfNull(credentialId);
            ArgumentNullException.ThrowIfNull(cosePublicKey);
            ms.Write(PasskeyIds.AaguidBytes);
            Span<byte> len = stackalloc byte[2];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)credentialId.Length);
            ms.Write(len);
            ms.Write(credentialId);
            ms.Write(cosePublicKey);
        }
        return ms.ToArray();
    }

    // COSE_Key for an ES256 public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    internal static byte[] EncodeCoseEs256PublicKey(ECParameters parameters)
    {
        byte[] x = parameters.Q.X ?? throw new InvalidOperationException("public key has no X coordinate");
        byte[] y = parameters.Q.Y ?? throw new InvalidOperationException("public key has no Y coordinate");

        var w = new CborWriter(CborConformanceMode.Ctap2Canonical);
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(2);            // kty: EC2
        w.WriteInt32(3); w.WriteInt32(CoseEs256);    // alg: ES256
        w.WriteInt32(-1); w.WriteInt32(1);           // crv: P-256
        w.WriteInt32(-2); w.WriteByteString(LeftPad(x, 32));
        w.WriteInt32(-3); w.WriteByteString(LeftPad(y, 32));
        w.WriteEndMap();
        return w.Encode();
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        if (value.Length == length) return value;
        if (value.Length > length) return value[^length..];
        byte[] padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    // --- response encoding -------------------------------------------------------------------

    internal static byte[] Error(CtapStatus status) => new[] { (byte)status };

    // authenticatorMakeCredential response: {1: fmt, 2: authData, 3: attStmt}. Passkeys use
    // "none" attestation - no attestation statement, which is what browsers ask for by default.
    internal static byte[] EncodeMakeCredentialResponse(byte[] authData)
    {
        var w = new CborWriter(CborConformanceMode.Ctap2Canonical);
        w.WriteStartMap(3);
        w.WriteInt32(0x01); w.WriteTextString("none");
        w.WriteInt32(0x02); w.WriteByteString(authData);
        w.WriteInt32(0x03); w.WriteStartMap(0); w.WriteEndMap();
        w.WriteEndMap();
        return w.Encode();
    }

    // authenticatorGetAssertion response: {1: credential, 2: authData, 3: signature, 4: user,
    // 5: numberOfCredentials}.
    internal static byte[] EncodeGetAssertionResponse(byte[] credentialId, byte[] authData, byte[] signature,
                                                      byte[] userId, string? userName, string? userDisplayName,
                                                      int numberOfCredentials)
    {
        bool withUser = userId.Length > 0;
        bool withCount = numberOfCredentials > 1;

        var w = new CborWriter(CborConformanceMode.Ctap2Canonical);
        w.WriteStartMap(3 + (withUser ? 1 : 0) + (withCount ? 1 : 0));

        w.WriteInt32(0x01);
        w.WriteStartMap(2);
        w.WriteTextString("id"); w.WriteByteString(credentialId);
        w.WriteTextString("type"); w.WriteTextString("public-key");
        w.WriteEndMap();

        w.WriteInt32(0x02); w.WriteByteString(authData);
        w.WriteInt32(0x03); w.WriteByteString(signature);

        if (withUser)
        {
            w.WriteInt32(0x04);
            int fields = 1 + (string.IsNullOrEmpty(userName) ? 0 : 1) + (string.IsNullOrEmpty(userDisplayName) ? 0 : 1);
            w.WriteStartMap(fields);
            w.WriteTextString("id"); w.WriteByteString(userId);
            if (!string.IsNullOrEmpty(userName)) { w.WriteTextString("name"); w.WriteTextString(userName); }
            if (!string.IsNullOrEmpty(userDisplayName)) { w.WriteTextString("displayName"); w.WriteTextString(userDisplayName); }
            w.WriteEndMap();
        }

        if (withCount) { w.WriteInt32(0x05); w.WriteInt32(numberOfCredentials); }

        w.WriteEndMap();
        return w.Encode();
    }
}
