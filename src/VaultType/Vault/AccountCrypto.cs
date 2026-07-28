using System.Security.Cryptography;
using VaultType.Models;
using VaultType.Security;
using VaultType.Services;
using VaultType.Vault.Crypto;
using VaultType.Vault.Models;

namespace VaultType.Vault;

// Holds the decrypted key material for one unlocked account and turns encrypted ciphers into
// plaintext VaultItems. Secrets (passwords, TOTP seeds) are pushed straight into a SecretProtector
// so they never linger as managed strings. Wiped on Dispose/lock.
public sealed class AccountCrypto : IDisposable
{
    private SymmetricCryptoKey? _userKey;
    private RSA? _rsa;
    private readonly Dictionary<string, SymmetricCryptoKey> _orgKeys = new();

    public bool IsUnlocked => _userKey != null;

    // Unwrap the user key (from the stretched master key), then the RSA private key and any org keys.
    public void Unlock(ReadOnlySpan<byte> masterKey, string protectedUserKey, string? protectedPrivateKey,
        IEnumerable<OrganizationModel> organizations)
    {
        using var stretched = Kdf.StretchMasterKey(masterKey);
        UnlockWithUserKeyRaw(EncString.Parse(protectedUserKey).DecryptSymmetric(stretched),
            protectedPrivateKey, organizations);
    }

    // Unlock directly from an already-unwrapped user key (PIN/biometric/passkey paths, or a persisted
    // user key). Takes ownership of userKeyRaw and wipes it.
    public void UnlockWithUserKeyRaw(byte[] userKeyRaw, string? protectedPrivateKey,
        IEnumerable<OrganizationModel> organizations)
    {
        try
        {
            _userKey = SymmetricCryptoKey.FromRaw(userKeyRaw);
        }
        finally { CryptographicOperations.ZeroMemory(userKeyRaw); }

        if (!string.IsNullOrEmpty(protectedPrivateKey))
        {
            byte[] pkcs8 = EncString.Parse(protectedPrivateKey).DecryptSymmetric(_userKey);
            try
            {
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(pkcs8, out _);
                _rsa = rsa;
            }
            finally { CryptographicOperations.ZeroMemory(pkcs8); }
        }

        if (_rsa != null)
        {
            foreach (var org in organizations)
            {
                if (string.IsNullOrEmpty(org.Id) || string.IsNullOrEmpty(org.Key)) continue;
                try
                {
                    byte[] orgRaw = EncString.Parse(org.Key).DecryptRsa(_rsa);
                    _orgKeys[org.Id] = SymmetricCryptoKey.FromRaw(orgRaw);
                    CryptographicOperations.ZeroMemory(orgRaw);
                }
                catch
                {
                    // Skip an org whose key we can't unwrap.
                }
            }
        }
    }

    // A copy of the raw user key (enc||mac) for wrapping into an unlock envelope (PIN etc.).
    // The caller must zero the returned buffer.
    public byte[] ExportUserKeyRaw()
    {
        var k = _userKey ?? throw new InvalidOperationException("Account is locked.");
        byte[] raw = new byte[k.EncKey.Length + (k.HasMac ? k.MacKey.Length : 0)];
        k.EncKey.CopyTo(raw);
        if (k.HasMac) k.MacKey.CopyTo(raw.AsSpan(k.EncKey.Length));
        return raw;
    }

    // The wrapping key for a cipher: the org key for org-owned items, else the user key.
    private SymmetricCryptoKey WrappingKey(string? organizationId)
    {
        if (!string.IsNullOrEmpty(organizationId) && _orgKeys.TryGetValue(organizationId, out var ok)) return ok;
        return _userKey ?? throw new InvalidOperationException("Account is locked.");
    }

    // Encrypt a value with the user key (for a fresh personal item that has no per-item key).
    public string EncryptWithUserKey(string plaintext)
        => EncString.EncryptString(plaintext, _userKey ?? throw new InvalidOperationException("Account is locked."));

    // Encrypt a value with a cipher's effective content key (per-item key if present, else wrapping key).
    public string EncryptForCipher(CipherModel c, string plaintext)
    {
        var (key, owns) = ContentKey(c);
        try { return EncString.EncryptString(plaintext, key); }
        finally { if (owns) key.Dispose(); }
    }

    // Resolve the effective content key for a cipher: its per-item key if present, else the wrapping key.
    // The returned key must be disposed by the caller ONLY if ownsKey is true.
    private (SymmetricCryptoKey key, bool ownsKey) ContentKey(CipherModel c)
    {
        var wrap = WrappingKey(c.OrganizationId);
        if (string.IsNullOrEmpty(c.Key)) return (wrap, false);
        byte[] raw = EncString.Parse(c.Key).DecryptSymmetric(wrap);
        var content = SymmetricCryptoKey.FromRaw(raw);
        CryptographicOperations.ZeroMemory(raw);
        return (content, true);
    }

    private string DecString(string? enc, SymmetricCryptoKey key)
        => string.IsNullOrEmpty(enc) ? "" : EncString.Parse(enc).DecryptToString(key);

    // Decrypt a login cipher into a VaultItem. Non-login types return null.
    public VaultItem? DecryptLogin(CipherModel c, SecretProtector protector, string autoTypeFieldName)
    {
        if (c.Type != 1 || c.Login == null) return null;
        var (key, owns) = ContentKey(c);
        try
        {
            var it = new VaultItem
            {
                Id = c.Id ?? "",
                Name = DecString(c.Name, key),
                Reprompt = c.Reprompt == 1,
                Username = DecString(c.Login.Username, key),
            };

            it.Password = ProtectDecrypted(c.Login.Password, key, protector);
            it.TotpSecret = ProtectDecrypted(c.Login.Totp, key, protector);
            it.HasTotp = it.TotpSecret != null;

            foreach (var u in c.Login.Uris)
            {
                if (string.IsNullOrEmpty(u.Uri)) continue;
                var iu = new ItemUri { Value = DecString(u.Uri, key), MatchType = u.Match };
                if (iu.Value.Length == 0) continue;
                Matcher.FillHostDomain(iu);
                it.Uris.Add(iu);
            }

            it.CustomSequence = ReadCustomSequence(c, key, autoTypeFieldName);
            return it;
        }
        finally { if (owns) key.Dispose(); }
    }

    // Decrypt a card cipher (type 3) into a VaultItem. Non-card types return null.
    // Number, security code and expiry go into the protector; brand, cardholder and the last four
    // digits stay plaintext so the picker can label the row without decrypting anything.
    public VaultItem? DecryptCard(CipherModel c, SecretProtector protector, string autoTypeFieldName)
    {
        if (c.Type != 3 || c.Card == null) return null;
        var (key, owns) = ContentKey(c);
        try
        {
            var card = new CardData
            {
                CardholderName = DecString(c.Card.CardholderName, key),
                Brand = DecString(c.Card.Brand, key),
            };
            card.Number = ProtectDecrypted(c.Card.Number, key, protector);
            card.Code = ProtectDecrypted(c.Card.Code, key, protector);
            card.ExpMonth = ProtectDecrypted(c.Card.ExpMonth, key, protector);
            card.ExpYear = ProtectDecrypted(c.Card.ExpYear, key, protector);
            card.Last4 = LastFourDigits(c.Card.Number, key);

            var it = new VaultItem
            {
                Id = c.Id ?? "",
                Kind = ItemKind.Card,
                Name = DecString(c.Name, key),
                Reprompt = c.Reprompt == 1,
                Card = card,
            };
            it.CustomSequence = ReadCustomSequence(c, key, autoTypeFieldName);
            it.CustomFields = ReadCustomFields(c, key, protector, autoTypeFieldName);
            return it;
        }
        finally { if (owns) key.Dispose(); }
    }

    // Decrypt an identity cipher (type 4) into a VaultItem. Non-identity types return null.
    // Only the first and last name stay plaintext - everything else is protected in RAM.
    public VaultItem? DecryptIdentity(CipherModel c, SecretProtector protector, string autoTypeFieldName)
    {
        if (c.Type != 4 || c.Identity == null) return null;
        var (key, owns) = ContentKey(c);
        try
        {
            var id = c.Identity;
            var data = new IdentityData
            {
                FirstName = DecString(id.FirstName, key),
                LastName = DecString(id.LastName, key),
                Title = ProtectDecrypted(id.Title, key, protector),
                MiddleName = ProtectDecrypted(id.MiddleName, key, protector),
                Address1 = ProtectDecrypted(id.Address1, key, protector),
                Address2 = ProtectDecrypted(id.Address2, key, protector),
                Address3 = ProtectDecrypted(id.Address3, key, protector),
                City = ProtectDecrypted(id.City, key, protector),
                State = ProtectDecrypted(id.State, key, protector),
                PostalCode = ProtectDecrypted(id.PostalCode, key, protector),
                Country = ProtectDecrypted(id.Country, key, protector),
                Company = ProtectDecrypted(id.Company, key, protector),
                Email = ProtectDecrypted(id.Email, key, protector),
                Phone = ProtectDecrypted(id.Phone, key, protector),
                Ssn = ProtectDecrypted(id.Ssn, key, protector),
                Username = ProtectDecrypted(id.Username, key, protector),
                PassportNumber = ProtectDecrypted(id.PassportNumber, key, protector),
                LicenseNumber = ProtectDecrypted(id.LicenseNumber, key, protector),
            };

            var it = new VaultItem
            {
                Id = c.Id ?? "",
                Kind = ItemKind.Identity,
                Name = DecString(c.Name, key),
                Reprompt = c.Reprompt == 1,
                Identity = data,
            };
            it.CustomSequence = ReadCustomSequence(c, key, autoTypeFieldName);
            it.CustomFields = ReadCustomFields(c, key, protector, autoTypeFieldName);
            return it;
        }
        finally { if (owns) key.Dispose(); }
    }

    // The per-entry auto-type sequence from the configured custom field, if the entry carries one.
    private string? ReadCustomSequence(CipherModel c, SymmetricCryptoKey key, string autoTypeFieldName)
    {
        string? seq = null;
        foreach (var f in c.Fields)
        {
            string name = DecString(f.Name, key);
            if (!string.Equals(name, autoTypeFieldName, StringComparison.OrdinalIgnoreCase)) continue;
            string val = DecString(f.Value, key);
            if (val.Length > 0) seq = val;
        }
        return seq;
    }

    // The entry's other custom fields, so a form field the built-in groups don't cover can still be
    // filled by naming it in the vault. Text and hidden fields only - a boolean or a linked field
    // has nothing to type. The auto-type sequence field is excluded; it is not form data.
    private List<CustomField> ReadCustomFields(CipherModel c, SymmetricCryptoKey key,
                                               SecretProtector protector, string autoTypeFieldName)
    {
        var list = new List<CustomField>();
        foreach (var f in c.Fields)
        {
            if (f.Type != 0 && f.Type != 1) continue;
            string name = DecString(f.Name, key);
            if (name.Length == 0) continue;
            if (string.Equals(name, autoTypeFieldName, StringComparison.OrdinalIgnoreCase)) continue;

            var value = ProtectDecrypted(f.Value, key, protector);
            if (value == null) continue;
            list.Add(new CustomField { Name = name, Value = value });
        }
        return list;
    }

    // The last four digits of a card number, for the picker row. Decrypted into a locked buffer and
    // wiped again - only the four digits survive as a managed string.
    private static string LastFourDigits(string? encNumber, SymmetricCryptoKey key)
    {
        if (string.IsNullOrEmpty(encNumber)) return "";
        byte[] pt = EncString.Parse(encNumber).DecryptSymmetric(key);
        try
        {
            Span<char> digits = stackalloc char[4];
            int n = 0;
            // Walk backwards and keep the last four digits, skipping spaces and dashes.
            for (int i = pt.Length - 1; i >= 0 && n < 4; i--)
            {
                char ch = (char)pt[i];
                if (ch >= '0' && ch <= '9') digits[3 - n++] = ch;
            }
            return n == 4 ? new string(digits) : "";
        }
        finally { CryptographicOperations.ZeroMemory(pt); }
    }

    // Decrypt an SSH-key cipher (type 5) into an SshKeyEntry. Non-SSH types return null.
    public SshKeyEntry? DecryptSshKey(CipherModel c, SecretProtector protector)
    {
        if (c.Type != 5 || c.SshKey == null) return null;
        var (key, owns) = ContentKey(c);
        try
        {
            var entry = new SshKeyEntry
            {
                Id = c.Id ?? "",
                Name = DecString(c.Name, key),
                Reprompt = c.Reprompt == 1,
                Fingerprint = DecString(c.SshKey.KeyFingerprint, key),
                PublicKey = DecString(c.SshKey.PublicKey, key),
            };
            entry.Type = SshKeyType(entry.PublicKey);
            entry.PrivateKey = ProtectDecrypted(c.SshKey.PrivateKey, key, protector);
            return entry;
        }
        finally { if (owns) key.Dispose(); }
    }

    // Decrypt the passkeys of a login cipher into Fido2Entry objects. Items without passkeys yield
    // an empty list; a credential that fails to decrypt is skipped rather than failing the rest.
    public List<Fido2Entry> DecryptFido2(CipherModel c, SecretProtector protector)
    {
        var list = new List<Fido2Entry>();
        if (c.Type != 1 || c.Login == null || c.Login.Fido2Credentials.Count == 0) return list;
        var (key, owns) = ContentKey(c);
        try
        {
            string itemName = DecString(c.Name, key);
            foreach (var f in c.Login.Fido2Credentials)
            {
                try
                {
                    var e = new Fido2Entry
                    {
                        ItemId = c.Id ?? "",
                        ItemName = itemName,
                        Reprompt = c.Reprompt == 1,
                        CredentialId = ParseCredentialId(DecString(f.CredentialId, key)),
                        RpId = DecString(f.RpId, key),
                        RpName = DecString(f.RpName, key),
                        UserName = DecString(f.UserName, key),
                        UserDisplayName = DecString(f.UserDisplayName, key),
                    };
                    string handle = DecString(f.UserHandle, key);
                    if (handle.Length > 0) e.UserHandle = Base64UrlDecode(handle);
                    _ = uint.TryParse(DecString(f.Counter, key), out e.Counter);
                    e.Discoverable = string.Equals(DecString(f.Discoverable, key), "true", StringComparison.OrdinalIgnoreCase);

                    // keyValue is the base64url PKCS#8 blob; decode before protecting so the
                    // ceremony can import it directly.
                    string kv = DecString(f.KeyValue, key);
                    if (kv.Length == 0 || e.CredentialId.Length == 0 || e.RpId.Length == 0) continue;
                    byte[] pkcs8 = Base64UrlDecode(kv);
                    try { e.PrivateKey = protector.Protect(pkcs8); }
                    finally { CryptographicOperations.ZeroMemory(pkcs8); }

                    list.Add(e);
                }
                catch { /* skip this credential */ }
            }
        }
        finally { if (owns) key.Dispose(); }
        return list;
    }

    // Bitwarden stores the credential id either as a GUID string (wire format: the 16 RFC 4122
    // bytes) or, prefixed "b64.", as base64url raw bytes.
    public static byte[] ParseCredentialId(string value)
    {
        if (string.IsNullOrEmpty(value)) return Array.Empty<byte>();
        if (value.StartsWith("b64.", StringComparison.Ordinal)) return Base64UrlDecode(value[4..]);
        return Guid.TryParse(value, out var g) ? g.ToByteArray(bigEndian: true) : Array.Empty<byte>();
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    // "ssh-ed25519 AAAA..." -> "ed25519"; "ssh-rsa AAAA..." -> "rsa-<bits>" (from the modulus length)
    private static string SshKeyType(string publicKey)
    {
        string trimmed = publicKey.TrimStart();
        int sp = trimmed.IndexOf(' ');
        string alg = sp > 0 ? trimmed[..sp] : trimmed;
        if (alg.StartsWith("ssh-ed25519", StringComparison.Ordinal)) return "ed25519";
        if (alg.StartsWith("ecdsa-sha2-nistp", StringComparison.Ordinal)) return "ecdsa-" + alg["ecdsa-sha2-nistp".Length..];
        if (alg == "ssh-rsa")
        {
            try
            {
                var parts = publicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                byte[] blob = Convert.FromBase64String(parts[1]);
                int o = 0;
                int ReadLen() { int l = (blob[o] << 24) | (blob[o + 1] << 16) | (blob[o + 2] << 8) | blob[o + 3]; o += 4; return l; }
                o += ReadLen();               // algorithm name
                o += ReadLen();               // public exponent
                int nLen = ReadLen();         // modulus (may carry a sign byte)
                int bits = (nLen - (blob[o] == 0 ? 1 : 0)) * 8;
                return "rsa-" + bits;
            }
            catch { return "rsa"; }
        }
        return alg.Length > 0 ? alg : "ssh";
    }

    // Decrypt an EncString into a locked buffer and hand it to the protector as a SecretBox.
    private static SecretBox? ProtectDecrypted(string? enc, SymmetricCryptoKey key, SecretProtector protector)
    {
        if (string.IsNullOrEmpty(enc)) return null;
        byte[] pt = EncString.Parse(enc).DecryptSymmetric(key);
        try
        {
            if (pt.Length == 0) return null;
            return protector.Protect(pt);
        }
        finally { CryptographicOperations.ZeroMemory(pt); }
    }

    public void Dispose()
    {
        _userKey?.Dispose(); _userKey = null;
        _rsa?.Dispose(); _rsa = null;
        foreach (var k in _orgKeys.Values) k.Dispose();
        _orgKeys.Clear();
    }
}
