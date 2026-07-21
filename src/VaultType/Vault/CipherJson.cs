using System.Text.Json;
using System.Text.Json.Nodes;
using VaultType.Vault.Models;

namespace VaultType.Vault;

// The encrypted field set of one fido2Credential, ready to be embedded in a cipher body.
public sealed class Fido2CredentialEnc
{
    public string CredentialId = "";     // EncString of the GUID string
    public string KeyType = "";          // EncString of "public-key"
    public string KeyAlgorithm = "";     // EncString of "ECDSA"
    public string KeyCurve = "";         // EncString of "P-256"
    public string KeyValue = "";         // EncString of the b64url PKCS#8 private key
    public string RpId = "";
    public string? RpName;
    public string? UserHandle;           // EncString of the b64url user id
    public string? UserName;
    public string? UserDisplayName;
    public string Counter = "";          // EncString of "0"
    public string Discoverable = "";     // EncString of "true"/"false"
}

// Builds the request bodies for creating and editing ciphers. Everything here operates on already-
// encrypted EncStrings (the values carried on CipherModel are ciphertext), so no plaintext is
// handled. The edit body is a read-modify-write that preserves every existing field verbatim.
public static class CipherJson
{
    // Append an encrypted URI to a login cipher and produce the full PUT body. Preserves the
    // per-item key, all existing encrypted fields, custom fields and fido2 credentials.
    public static string BuildAddUriBody(CipherModel c, string encryptedUri)
    {
        var login = new JsonObject
        {
            ["username"] = c.Login?.Username,
            ["password"] = c.Login?.Password,
            ["totp"] = c.Login?.Totp,
        };

        var uris = new JsonArray();
        if (c.Login != null)
            foreach (var u in c.Login.Uris)
                uris.Add(new JsonObject { ["uri"] = u.Uri, ["match"] = u.Match });
        uris.Add(new JsonObject { ["uri"] = encryptedUri, ["match"] = null });
        login["uris"] = uris;

        // Preserve passkeys verbatim if the item carries any.
        if (TryGetArray(c.Raw, "login", "fido2Credentials", out var fido)) login["fido2Credentials"] = fido;

        var body = new JsonObject
        {
            ["type"] = c.Type,
            ["name"] = c.Name,
            ["notes"] = c.Notes,
            ["favorite"] = c.Favorite,
            ["reprompt"] = c.Reprompt,
            ["organizationId"] = c.OrganizationId,
            ["folderId"] = c.FolderId,
            ["key"] = c.Key,
            ["login"] = login,
            ["lastKnownRevisionDate"] = c.RevisionDate?.UtcDateTime.ToString("o"),
        };
        if (TryGetArray(c.Raw, "fields", out var fields)) body["fields"] = fields;

        return body.ToJsonString();
    }

    // A minimal new personal login (encrypted fields supplied by the caller). Used by the dev test.
    public static string BuildCreateLogin(string encName, string? encUsername, string? encPassword,
        string? encTotp, IEnumerable<string> encUris)
    {
        var uris = new JsonArray();
        foreach (var u in encUris) uris.Add(new JsonObject { ["uri"] = u, ["match"] = null });
        var body = new JsonObject
        {
            ["type"] = 1,
            ["name"] = encName,
            ["notes"] = null,
            ["favorite"] = false,
            ["reprompt"] = 0,
            ["login"] = new JsonObject
            {
                ["username"] = encUsername,
                ["password"] = encPassword,
                ["totp"] = encTotp,
                ["uris"] = uris,
            },
            ["fields"] = new JsonArray(),
            ["lastKnownRevisionDate"] = null,
        };
        return body.ToJsonString();
    }

    // A new personal login carrying one passkey (all values already encrypted). Created when a
    // relying party registers a passkey through the Windows plugin authenticator.
    public static string BuildCreateFido2Login(string encName, string? encUsername, string encUri,
        Fido2CredentialEnc cred)
    {
        var body = new JsonObject
        {
            ["type"] = 1,
            ["name"] = encName,
            ["notes"] = null,
            ["favorite"] = false,
            ["reprompt"] = 0,
            ["login"] = new JsonObject
            {
                ["username"] = encUsername,
                ["password"] = null,
                ["totp"] = null,
                ["uris"] = new JsonArray(new JsonObject { ["uri"] = encUri, ["match"] = null }),
                ["fido2Credentials"] = new JsonArray(new JsonObject
                {
                    ["credentialId"] = cred.CredentialId,
                    ["keyType"] = cred.KeyType,
                    ["keyAlgorithm"] = cred.KeyAlgorithm,
                    ["keyCurve"] = cred.KeyCurve,
                    ["keyValue"] = cred.KeyValue,
                    ["rpId"] = cred.RpId,
                    ["rpName"] = cred.RpName,
                    ["userHandle"] = cred.UserHandle,
                    ["userName"] = cred.UserName,
                    ["userDisplayName"] = cred.UserDisplayName,
                    ["counter"] = cred.Counter,
                    ["discoverable"] = cred.Discoverable,
                    ["creationDate"] = DateTime.UtcNow.ToString("o"),
                }),
            },
            ["fields"] = new JsonArray(),
            ["lastKnownRevisionDate"] = null,
        };
        return body.ToJsonString();
    }

    private static bool TryGetArray(JsonElement root, string prop, out JsonNode? node)
        => TryGetArray(root, null, prop, out node);

    private static bool TryGetArray(JsonElement root, string? parent, string prop, out JsonNode? node)
    {
        node = null;
        if (root.ValueKind != JsonValueKind.Object) return false;
        JsonElement scope = root;
        if (parent != null)
        {
            if (!root.TryGetProperty(parent, out scope) || scope.ValueKind != JsonValueKind.Object) return false;
        }
        if (!scope.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array) return false;
        node = JsonNode.Parse(arr.GetRawText());
        return node != null;
    }
}
