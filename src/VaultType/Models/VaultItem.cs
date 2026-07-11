using VaultType.Security;

namespace VaultType.Models;

// One URI of an entry, with its match type and precomputed host/domain.
public sealed class ItemUri
{
    public string Value { get; set; } = "";
    public int MatchType { get; set; }   // 0=Domain,1=Host,2=StartsWith,3=Exact,4=Regex,5=Never
    public string Host { get; set; } = "";
    public string Domain { get; set; } = "";
}

// A login entry. Display fields (Name/Username/URI) are plaintext; the password and TOTP
// secret stay encrypted in RAM (SecretBox). These have to be properties, not fields, or WPF
// data binding won't pick them up.
public sealed class VaultItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Username { get; set; } = "";
    public bool Reprompt { get; set; }
    public bool HasTotp { get; set; }
    public string? CustomSequence { get; set; }
    public List<ItemUri> Uris { get; set; } = new();
    public SecretBox? Password { get; set; }
    public SecretBox? TotpSecret { get; set; }

    public string PrimaryHost => Uris.Count > 0 ? Uris[0].Host : "";
    public string PrimaryUri => Uris.Count > 0 ? Uris[0].Value : "";

    // case-insensitive search over name, username and URIs (nothing secret)
    public bool Matches(string term)
    {
        if (Name.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;
        if (Username.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var u in Uris)
            if (u.Value.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
