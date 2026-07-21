using System.Security.Cryptography;
using System.Text;

namespace VaultType.Vault.Crypto;

// Known-answer + round-trip checks for the crypto foundation. Run via the "--cryptotest" dev mode;
// verifies the wiring (unit conversions, salt handling, MAC) before it touches a real vault.
// Full protocol correctness is verified separately against a live vault (compared with bw.exe).
public static class CryptoSelfTest
{
    public static string Run()
    {
        var sb = new StringBuilder();
        int passed = 0, failed = 0;

        void Check(string name, bool ok, string? detail = null)
        {
            if (ok) { passed++; sb.AppendLine($"  PASS  {name}"); }
            else { failed++; sb.AppendLine($"  FAIL  {name}{(detail != null ? " -- " + detail : "")}"); }
        }

        // --- PBKDF2-SHA256 known-answer vectors (password="password", salt="salt") ---
        {
            byte[] pw = "password"u8.ToArray();
            byte[] salt = "salt"u8.ToArray();
            string h1 = Convert.ToHexString(Kdf.Pbkdf2(pw, salt, 1, 32)).ToLowerInvariant();
            string h2 = Convert.ToHexString(Kdf.Pbkdf2(pw, salt, 2, 32)).ToLowerInvariant();
            Check("PBKDF2-SHA256 iters=1", h1 == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", h1);
            Check("PBKDF2-SHA256 iters=2", h2 == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", h2);
        }

        // --- HKDF-Expand self-consistency (deterministic, distinct per info) ---
        {
            byte[] prk = RandomNumberGenerator.GetBytes(32);
            byte[] a1 = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "enc"u8.ToArray());
            byte[] a2 = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "enc"u8.ToArray());
            byte[] b = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "mac"u8.ToArray());
            Check("HKDF-Expand deterministic", a1.AsSpan().SequenceEqual(a2));
            Check("HKDF-Expand info-separated", !a1.AsSpan().SequenceEqual(b));
        }

        // --- Argon2id RFC 9106 §5.3 known-answer vector (our own managed implementation) ---
        {
            byte[] pw = new byte[32]; Array.Fill(pw, (byte)0x01);
            byte[] salt = new byte[16]; Array.Fill(salt, (byte)0x02);
            byte[] secret = new byte[8]; Array.Fill(secret, (byte)0x03);
            byte[] ad = new byte[12]; Array.Fill(ad, (byte)0x04);
            string kat = Convert.ToHexString(
                Argon2id.Hash(pw, salt, parallelism: 4, memoryKiB: 32, iterations: 3, outLen: 32, secret: secret, associatedData: ad))
                .ToLowerInvariant();
            Check("Argon2id RFC 9106 KAT", kat == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", kat);
        }

        // --- Argon2id: determinism + salt sensitivity at Bitwarden-scale params ---
        {
            byte[] pw = "password"u8.ToArray();
            byte[] salt1 = SHA256.HashData("nobody@example.com"u8.ToArray());
            byte[] salt2 = SHA256.HashData("other@example.com"u8.ToArray());
            byte[] o1 = Kdf.Argon2id(pw, salt1, iterations: 3, memoryKiB: 64 * 1024, parallelism: 4, length: 32);
            byte[] o1b = Kdf.Argon2id(pw, salt1, iterations: 3, memoryKiB: 64 * 1024, parallelism: 4, length: 32);
            byte[] o2 = Kdf.Argon2id(pw, salt2, iterations: 3, memoryKiB: 64 * 1024, parallelism: 4, length: 32);
            Check("Argon2id length=32", o1.Length == 32);
            Check("Argon2id deterministic", o1.AsSpan().SequenceEqual(o1b));
            Check("Argon2id salt-sensitive", !o1.AsSpan().SequenceEqual(o2));
        }

        // --- Ed25519 RFC 8032 §7.1 known-answer vector (our own managed implementation) ---
        {
            byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            string pub = Convert.ToHexString(Ed25519.PublicKeyFromSeed(seed)).ToLowerInvariant();
            string sig = Convert.ToHexString(Ed25519.Sign(seed, ReadOnlySpan<byte>.Empty)).ToLowerInvariant();
            Check("Ed25519 pubkey KAT", pub == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pub);
            Check("Ed25519 signature KAT",
                sig == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", sig);
        }

        // --- EncString type-2 round-trip (AES-256-CBC + HMAC-SHA256) ---
        {
            using var key = SymmetricCryptoKey.FromRaw(RandomNumberGenerator.GetBytes(64));
            const string secret = "correct horse battery staple - äöü 🔐";
            string enc = EncString.EncryptString(secret, key);
            var parsed = EncString.Parse(enc);
            string dec = parsed.DecryptToString(key);
            Check("EncString type-2 round-trip", dec == secret, dec);
            Check("EncString type is 2", parsed.Type == 2, parsed.Type.ToString());

            // MAC tamper must be rejected
            byte[] iv = parsed.Iv, data = parsed.Data, mac = parsed.Mac!;
            data[0] ^= 0xFF;
            string tampered = $"2.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(data)}|{Convert.ToBase64String(mac)}";
            bool threw = false;
            try { EncString.Parse(tampered).DecryptSymmetric(key); } catch (CryptographicException) { threw = true; }
            Check("EncString MAC tamper rejected", threw);

            // Wrong key must be rejected by the MAC check
            using var wrong = SymmetricCryptoKey.FromRaw(RandomNumberGenerator.GetBytes(64));
            bool threw2 = false;
            try { EncString.Parse(enc).DecryptSymmetric(wrong); } catch (CryptographicException) { threw2 = true; }
            Check("EncString wrong-key rejected", threw2);
        }

        // --- Master-key pipeline: derive -> stretch -> unwrap a user key we wrapped ourselves ---
        {
            byte[] pw = "Sup3rSecretMasterKey!42"u8.ToArray();
            byte[] masterKey = Kdf.DeriveMasterKey("alex.doe@example.com", pw, KdfConfig.Pbkdf2(600_000));
            Check("Master key length=32", masterKey.Length == 32);

            string authHash = Kdf.MasterPasswordAuthHash(masterKey, pw);
            string localHash = Kdf.LocalAuthHash(masterKey, pw);
            Check("Auth hash != local hash (domain sep)", authHash != localHash);

            using var stretched = Kdf.StretchMasterKey(masterKey);
            // Wrap a fresh 64-byte user key with the stretched master key, then unwrap it.
            byte[] userKeyRaw = RandomNumberGenerator.GetBytes(64);
            string wrapped = EncString.EncryptSymmetric(userKeyRaw, stretched);
            byte[] unwrapped = EncString.Parse(wrapped).DecryptSymmetric(stretched);
            Check("User-key wrap/unwrap", userKeyRaw.AsSpan().SequenceEqual(unwrapped));
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(userKeyRaw);
            CryptographicOperations.ZeroMemory(unwrapped);
        }

        // --- RSA-OAEP-SHA1 (type 4) round-trip, mirroring org-key unwrapping ---
        {
            using var rsa = RSA.Create(2048);
            byte[] orgKey = RandomNumberGenerator.GetBytes(64);
            byte[] ct = rsa.Encrypt(orgKey, RSAEncryptionPadding.OaepSHA1);
            string enc = $"4.{Convert.ToBase64String(ct)}";
            byte[] pt = EncString.Parse(enc).DecryptRsa(rsa);
            Check("RSA-OAEP-SHA1 (type 4) round-trip", orgKey.AsSpan().SequenceEqual(pt));
        }

        // --- SecureString -> UTF-8 marshaling (used to hand the master password to the backend) ---
        {
            const string s = "P@ss-wörd-🔐-123";
            using var ss = new System.Security.SecureString();
            foreach (char ch in s) ss.AppendChar(ch);
            ss.MakeReadOnly();
            byte[] viaHelper = Security.SecureStringUtil.ToUtf8Bytes(ss);
            byte[] expected = Encoding.UTF8.GetBytes(s);
            Check("SecureString->UTF8 matches", viaHelper.AsSpan().SequenceEqual(expected));
        }

        sb.Insert(0, $"VaultType crypto self-test: {passed} passed, {failed} failed\n");
        return sb.ToString();
    }
}
