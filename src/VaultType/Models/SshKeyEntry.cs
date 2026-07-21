using VaultType.Security;

namespace VaultType.Models;

// One decrypted SSH key from the vault (cipher type 5). The private key (OpenSSH PEM) sits in a
// SecretBox and is only revealed for the moment of signing.
public sealed class SshKeyEntry
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";          // "ed25519", "rsa-4096", ...
    public string Fingerprint { get; set; } = "";   // "SHA256:..."
    public string PublicKey { get; set; } = "";     // authorized_keys line
    public SecretBox? PrivateKey { get; set; }      // OpenSSH private key PEM
}
