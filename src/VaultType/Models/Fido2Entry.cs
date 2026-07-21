using VaultType.Security;

namespace VaultType.Models;

// A decrypted passkey (FIDO2 discoverable credential) from a login cipher. The private key stays
// AES-GCM-protected in RAM (SecretBox) like every other secret; everything else is metadata the
// ceremony needs to match and answer a WebAuthn request.
public sealed class Fido2Entry
{
    public string ItemId = "";          // owning cipher
    public string ItemName = "";

    public byte[] CredentialId = Array.Empty<byte>();   // wire format (16 GUID bytes or raw b64 payload)
    public string RpId = "";
    public string RpName = "";
    public byte[] UserHandle = Array.Empty<byte>();
    public string UserName = "";
    public string UserDisplayName = "";
    public uint Counter;
    public bool Discoverable;

    // PKCS#8 ECDSA P-256 private key (the decoded keyValue), protected by the session's protector.
    public SecretBox? PrivateKey;
}
