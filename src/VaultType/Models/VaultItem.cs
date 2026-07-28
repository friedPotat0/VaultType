using VaultType.Security;

namespace VaultType.Models;

// One URI of an entry, with its match type and precomputed host/domain.
public sealed class ItemUri
{
    public string Value { get; set; } = "";
    public int? MatchType { get; set; }   // null = use the configured default; 0=Domain,1=Host,2=StartsWith,3=Exact,4=Regex,5=Never
    public string Host { get; set; } = "";
    public string Domain { get; set; } = "";
}

// Which cipher type an entry came from.
public enum ItemKind { Login, Card, Identity }

// A single field of an entry, as addressed by the picker's context menu and by the typing engine.
// None means "the whole entry", i.e. the custom or default sequence.
public enum ItemField
{
    None,
    Username, Password, Totp,
    CardNumber, CardCode, CardExpiry, CardHolder,
    IdName, IdEmail, IdPhone, IdAddress,
}

// The card fields of a type-3 cipher. Number, security code and expiry stay encrypted in RAM; the
// brand, the cardholder and the last four digits are kept in the clear so the picker can tell two
// cards apart without decrypting anything.
public sealed class CardData
{
    public string CardholderName { get; set; } = "";
    public string Brand { get; set; } = "";
    public string Last4 { get; set; } = "";
    public SecretBox? Number { get; set; }
    public SecretBox? Code { get; set; }
    public SecretBox? ExpMonth { get; set; }
    public SecretBox? ExpYear { get; set; }

    public bool HasNumber => Number != null;
    public bool HasCode => Code != null;
    public bool HasExpiry => ExpMonth != null || ExpYear != null;
}

// The identity fields of a type-4 cipher. Only the first and last name stay in the clear - they are
// what the picker shows and searches; everything else is protected in RAM.
public sealed class IdentityData
{
    public string FirstName { get; set; } = "";
    public string LastName { get; set; } = "";

    public SecretBox? Title { get; set; }
    public SecretBox? MiddleName { get; set; }
    public SecretBox? Address1 { get; set; }
    public SecretBox? Address2 { get; set; }
    public SecretBox? Address3 { get; set; }
    public SecretBox? City { get; set; }
    public SecretBox? State { get; set; }
    public SecretBox? PostalCode { get; set; }
    public SecretBox? Country { get; set; }
    public SecretBox? Company { get; set; }
    public SecretBox? Email { get; set; }
    public SecretBox? Phone { get; set; }
    public SecretBox? Ssn { get; set; }
    public SecretBox? Username { get; set; }
    public SecretBox? PassportNumber { get; set; }
    public SecretBox? LicenseNumber { get; set; }

    public string FullName => string.Join(" ",
        new[] { FirstName, LastName }.Where(p => p.Length > 0));

    public bool HasEmail => Email != null;
    public bool HasPhone => Phone != null;
    public bool HasAddress => Address1 != null || City != null || PostalCode != null;
}

// A custom field the user added to the entry in Bitwarden. The name stays plaintext because it is
// what gets matched against the form's field labels; the value is protected like every other secret.
public sealed class CustomField
{
    public string Name { get; set; } = "";
    public SecretBox? Value { get; set; }
}

// A vault entry. Display fields (Name/Username/URI) are plaintext; the password and TOTP
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

    public ItemKind Kind { get; set; } = ItemKind.Login;
    public CardData? Card { get; set; }
    public IdentityData? Identity { get; set; }

    // Custom fields carried by the entry, matched against form labels when filling. The field
    // holding the auto-type sequence is not part of this list.
    public List<CustomField> CustomFields { get; set; } = new();

    public string PrimaryHost => Uris.Count > 0 ? Uris[0].Host : "";

    // Used by the picker to hide menu entries for absent fields, and by the dispatcher so a
    // keyboard shortcut can't fire an action the menu wouldn't have offered.
    public bool Has(ItemField field) => field switch
    {
        ItemField.None => true,
        ItemField.Username => !string.IsNullOrEmpty(Username),
        ItemField.Password => Password != null,
        ItemField.Totp => HasTotp,
        ItemField.CardNumber => Card?.HasNumber == true,
        ItemField.CardCode => Card?.HasCode == true,
        ItemField.CardExpiry => Card?.HasExpiry == true,
        ItemField.CardHolder => !string.IsNullOrEmpty(Card?.CardholderName),
        ItemField.IdName => !string.IsNullOrEmpty(Identity?.FullName),
        ItemField.IdEmail => Identity?.HasEmail == true,
        ItemField.IdPhone => Identity?.HasPhone == true,
        ItemField.IdAddress => Identity?.HasAddress == true,
        _ => false,
    };

    // case-insensitive search over the entry's plaintext fields (nothing secret)
    public bool Matches(string term)
    {
        if (Name.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;

        switch (Kind)
        {
            case ItemKind.Card:
                if (Card == null) return false;
                return Card.Brand.Contains(term, StringComparison.OrdinalIgnoreCase)
                    || Card.Last4.Contains(term, StringComparison.OrdinalIgnoreCase)
                    || Card.CardholderName.Contains(term, StringComparison.OrdinalIgnoreCase);

            case ItemKind.Identity:
                // Only the name is plaintext - the remaining fields are protected and can't be
                // searched without decrypting them.
                if (Identity == null) return false;
                return Identity.FirstName.Contains(term, StringComparison.OrdinalIgnoreCase)
                    || Identity.LastName.Contains(term, StringComparison.OrdinalIgnoreCase);

            default:
                if (Username.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;
                foreach (var u in Uris)
                    if (u.Value.Contains(term, StringComparison.OrdinalIgnoreCase)) return true;
                return false;
        }
    }
}
