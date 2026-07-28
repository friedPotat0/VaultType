using VaultType.Models;

namespace VaultType.Services;

// Human-readable names for entry fields and lookup groups, used by the picker menu and by the
// messages shown when a field couldn't be located.
public static class FieldLabels
{
    public static string Key(ItemField field) => field switch
    {
        ItemField.Username => "field.username",
        ItemField.Password => "field.password",
        ItemField.Totp => "field.totp",
        ItemField.CardNumber => "field.cardNumber",
        ItemField.CardCode => "field.cardCode",
        ItemField.CardExpiry => "field.cardExpiry",
        ItemField.CardHolder => "field.cardHolder",
        ItemField.IdName => "field.idName",
        ItemField.IdEmail => "field.idEmail",
        ItemField.IdPhone => "field.idPhone",
        ItemField.IdAddress => "field.idAddress",
        _ => "field.entry",
    };

    public static string Text(ItemField field) => Loc.T(Key(field));

    // The name to show for a failed lookup. Groups the default sequences use get a translated
    // label; anything else (a term the user wrote in {FIELD "..."}) is echoed back verbatim, which
    // is exactly what they need to see to fix their sequence.
    public static string ForLookup(string groupOrTerm)
    {
        if (!Enum.TryParse<FieldGroup>(groupOrTerm, out var g)) return groupOrTerm;
        return g switch
        {
            FieldGroup.CardNumber => Loc.T("field.cardNumber"),
            FieldGroup.CardCode => Loc.T("field.cardCode"),
            FieldGroup.CardExpiry or FieldGroup.CardExpMonth or FieldGroup.CardExpYear => Loc.T("field.cardExpiry"),
            FieldGroup.CardHolder => Loc.T("field.cardHolder"),
            FieldGroup.FirstName or FieldGroup.LastName or FieldGroup.FullName => Loc.T("field.idName"),
            FieldGroup.Email => Loc.T("field.idEmail"),
            FieldGroup.Phone => Loc.T("field.idPhone"),
            _ => groupOrTerm,
        };
    }
}
