using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultType.Vault.Models;

// DTOs for the Bitwarden/Vaultwarden identity + api endpoints. The server may answer in PascalCase
// (classic) or camelCase (current/Vaultwarden), so everything is parsed case-insensitively.
internal static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

public sealed class PreloginResponse
{
    public int Kdf { get; set; }
    public int KdfIterations { get; set; } = 600_000;
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }
}

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    [JsonPropertyName("token_type")] public string? TokenType { get; set; }
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }

    // Protected keys (only returned on the initial password/apikey grant, not on refresh).
    public string? Key { get; set; }
    public string? PrivateKey { get; set; }

    // KDF echoed back on some servers.
    public int? Kdf { get; set; }
    public int? KdfIterations { get; set; }
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }

    // Error / 2FA fields (HTTP 400).
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("error_description")] public string? ErrorDescription { get; set; }
    public JsonElement TwoFactorProviders2 { get; set; }
    [JsonPropertyName("TwoFactorProviders")] public JsonElement TwoFactorProviders { get; set; }
    public JsonElement MasterPasswordPolicy { get; set; }

    public bool Requires2Fa => string.Equals(Error, "invalid_grant", StringComparison.OrdinalIgnoreCase)
        && ErrorDescription != null
        && ErrorDescription.Contains("two factor", StringComparison.OrdinalIgnoreCase);
}

// ---- sync ----

public sealed class SyncResponse
{
    public ProfileModel? Profile { get; set; }
    public List<CipherModel> Ciphers { get; set; } = new();
    public List<FolderModel> Folders { get; set; } = new();
}

public sealed class ProfileModel
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? Key { get; set; }
    public string? PrivateKey { get; set; }
    public List<OrganizationModel> Organizations { get; set; } = new();
}

public sealed class OrganizationModel
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Key { get; set; }   // RSA (type 4) wrapped org key
    public bool Enabled { get; set; }
}

public sealed class FolderModel
{
    public string? Id { get; set; }
    public string? Name { get; set; }   // EncString
}

public sealed class CipherModel
{
    public string? Id { get; set; }
    public string? OrganizationId { get; set; }
    public string? FolderId { get; set; }
    public int Type { get; set; }        // 1=login 2=note 3=card 4=identity 5=sshKey
    public string? Name { get; set; }    // EncString
    public string? Notes { get; set; }   // EncString
    public bool Favorite { get; set; }
    public int Reprompt { get; set; }    // 0=none 1=password
    public string? Key { get; set; }     // per-item content key (EncString) or null
    public LoginModel? Login { get; set; }
    public SshKeyModel? SshKey { get; set; }
    public CardModel? Card { get; set; }
    public IdentityModel? Identity { get; set; }
    public List<FieldModel> Fields { get; set; } = new();
    public DateTimeOffset? RevisionDate { get; set; }
    public DateTimeOffset? DeletedDate { get; set; }   // non-null = the item sits in the trash

    // Kept verbatim for read-modify-write on edit.
    public JsonElement Raw { get; set; }
}

public sealed class LoginModel
{
    public string? Username { get; set; }   // EncString
    public string? Password { get; set; }   // EncString
    public string? Totp { get; set; }       // EncString
    public List<UriModel> Uris { get; set; } = new();
    public List<Fido2CredentialModel> Fido2Credentials { get; set; } = new();
}

public sealed class UriModel
{
    public string? Uri { get; set; }   // EncString
    public int? Match { get; set; }
}

public sealed class SshKeyModel
{
    public string? PrivateKey { get; set; }     // EncString (OpenSSH PEM)
    public string? PublicKey { get; set; }       // EncString
    public string? KeyFingerprint { get; set; }  // EncString (may be absent on older Vaultwarden)
}

// A card cipher (type 3). Every value is an EncString.
public sealed class CardModel
{
    public string? CardholderName { get; set; }
    public string? Brand { get; set; }      // "Visa", "Mastercard", "Other", ...
    public string? Number { get; set; }
    public string? ExpMonth { get; set; }   // "1".."12" - Bitwarden does not pad it
    public string? ExpYear { get; set; }
    public string? Code { get; set; }       // CVV/CVC
}

// An identity cipher (type 4). Every value is an EncString.
public sealed class IdentityModel
{
    public string? Title { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string? LastName { get; set; }
    public string? Address1 { get; set; }
    public string? Address2 { get; set; }
    public string? Address3 { get; set; }
    public string? City { get; set; }
    public string? State { get; set; }
    public string? PostalCode { get; set; }
    public string? Country { get; set; }
    public string? Company { get; set; }
    public string? Email { get; set; }
    public string? Phone { get; set; }
    public string? Ssn { get; set; }
    public string? Username { get; set; }
    public string? PassportNumber { get; set; }
    public string? LicenseNumber { get; set; }
}

public sealed class Fido2CredentialModel
{
    public string? CredentialId { get; set; }
    public string? KeyType { get; set; }
    public string? KeyAlgorithm { get; set; }
    public string? KeyCurve { get; set; }
    public string? KeyValue { get; set; }        // EncString: PKCS#8 private key (b64url)
    public string? RpId { get; set; }
    public string? RpName { get; set; }
    public string? UserHandle { get; set; }
    public string? UserName { get; set; }
    public string? UserDisplayName { get; set; }
    public string? Counter { get; set; }
    public string? Discoverable { get; set; }
    public DateTimeOffset? CreationDate { get; set; }
}

public sealed class FieldModel
{
    public string? Name { get; set; }   // EncString
    public string? Value { get; set; }  // EncString
    public int Type { get; set; }       // 0=text 1=hidden 2=boolean 3=linked
}
