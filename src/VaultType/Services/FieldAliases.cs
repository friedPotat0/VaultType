namespace VaultType.Services;

// The field a {FIELD ...} lookup is after; the spellings behind each one live in FieldAliases.
public enum FieldGroup
{
    None,
    CardNumber, CardHolder, CardExpMonth, CardExpYear, CardExpiry, CardCode,
    Title, FirstName, MiddleName, LastName, FullName,
    Company, Email, Phone, Username,
    Address1, Address2, Address3, StreetName, HouseNumber, City, State, PostalCode, Country,
    Ssn, Passport, License,
}

// Maps field groups to the labels and identifiers forms use for them. Lookup works in both
// directions: {FIELD "CVV"} and {FIELD "Prüfziffer"} both resolve to CardCode and then search for
// every spelling in that group, so the user names the concept rather than the form's wording.
//
// Deliberately not exhaustive - it covers the common English and German spellings plus the
// standardised autocomplete tokens, which are language independent and therefore the most reliable
// anchor. Users extend it through AppConfig.FieldAliases for anything exotic.
public static class FieldAliases
{
    private static readonly Dictionary<FieldGroup, string[]> Builtin = new()
    {
        [FieldGroup.CardNumber] = new[]
        {
            "card number", "cardnumber", "credit card number", "creditcardnumber", "cc-number",
            "ccnumber", "cardnum", "card no", "kartennummer", "kreditkartennummer",
            "numero de tarjeta", "numero de carte", "numero carta",
        },
        [FieldGroup.CardHolder] = new[]
        {
            "cardholder", "cardholder name", "card holder", "name on card", "cc-name", "ccname",
            "karteninhaber", "name auf der karte", "titular", "titulaire",
        },
        [FieldGroup.CardExpMonth] = new[]
        {
            "exp month", "expiry month", "expiration month", "cc-exp-month", "ccexpmonth",
            "ablaufmonat", "gueltig bis monat", "monat", "month", "mm",
        },
        [FieldGroup.CardExpYear] = new[]
        {
            "exp year", "expiry year", "expiration year", "cc-exp-year", "ccexpyear",
            "ablaufjahr", "gueltig bis jahr", "jahr", "year", "yy", "yyyy",
        },
        [FieldGroup.CardExpiry] = new[]
        {
            "expiry", "expiry date", "expiration", "expiration date", "exp date", "valid thru",
            "cc-exp", "ccexp", "mm/yy", "mm / yy", "ablaufdatum", "gueltig bis", "gultig bis",
        },
        [FieldGroup.CardCode] = new[]
        {
            "cvv", "cvc", "cvv2", "cvc2", "csc", "cid", "cc-csc", "cccsc",
            "security code", "card security code", "card verification", "card verification value",
            "pruefziffer", "prufziffer", "sicherheitscode", "kartenpruefnummer", "kartenprufnummer",
            "code de securite", "codigo de seguridad",
        },

        [FieldGroup.Title] = new[] { "title", "salutation", "honorific-prefix", "anrede", "titel" },
        [FieldGroup.FirstName] = new[]
        {
            "first name", "firstname", "given name", "given-name", "forename",
            "vorname", "prenom", "nombre",
        },
        [FieldGroup.MiddleName] = new[]
        {
            "middle name", "middlename", "additional-name", "zweiter vorname", "mittlerer name",
        },
        [FieldGroup.LastName] = new[]
        {
            "last name", "lastname", "surname", "family name", "family-name",
            "nachname", "familienname", "nom", "apellido",
        },
        [FieldGroup.FullName] = new[]
        {
            "full name", "fullname", "name", "vollstaendiger name", "vollstandiger name",
            "vor und nachname", "nombre completo", "nom complet",
        },

        [FieldGroup.Company] = new[]
        {
            "company", "company name", "organization", "organisation",
            "firma", "unternehmen", "empresa", "entreprise",
        },
        [FieldGroup.Email] = new[]
        {
            "email", "e-mail", "email address", "e-mail address", "mail",
            "e-mail-adresse", "e-mail adresse", "emailadresse", "correo", "courriel",
        },
        [FieldGroup.Phone] = new[]
        {
            "phone", "phone number", "telephone", "tel", "mobile", "mobile phone", "cell",
            "telefon", "telefonnummer", "mobil", "handy", "rufnummer", "telefono", "telephone",
        },
        [FieldGroup.Username] = new[]
        {
            "username", "user name", "userid", "user id", "login", "login name",
            "benutzername", "nutzername", "anmeldename", "usuario", "identifiant",
        },

        [FieldGroup.Address1] = new[]
        {
            "address", "address line 1", "address-line1", "addressline1", "street", "street address",
            "strasse", "straße", "strasse und hausnummer", "adresse", "adresszeile 1",
            "direccion", "rue",
        },
        [FieldGroup.Address2] = new[]
        {
            "address line 2", "address-line2", "addressline2", "apartment", "suite",
            "adresszusatz", "adresszeile 2", "zusatz",
        },
        [FieldGroup.Address3] = new[] { "address line 3", "address-line3", "addressline3", "adresszeile 3" },
        // Forms that split the street from the house number. Only used when such a field is
        // actually present - otherwise the whole address line goes into the street field.
        [FieldGroup.StreetName] = new[]
        {
            "street name", "streetname", "strassenname", "nur strasse", "strasse ohne hausnummer",
        },
        // Deliberately no bare "nr" or "nummer": on a form spelling its card field "Karten Nummer"
        // those would match and put the house number into it.
        [FieldGroup.HouseNumber] = new[]
        {
            "house number", "housenumber", "house no", "street number", "streetnumber",
            "building number", "hausnummer", "haus nummer", "haus nr", "hausnr", "numero civico",
        },
        [FieldGroup.City] = new[]
        {
            "city", "town", "locality", "address-level2", "stadt", "ort", "wohnort", "ciudad", "ville",
        },
        [FieldGroup.State] = new[]
        {
            "state", "province", "region", "county", "address-level1",
            "bundesland", "kanton", "provincia",
        },
        [FieldGroup.PostalCode] = new[]
        {
            "postal code", "postalcode", "postal-code", "postcode", "post code", "zip", "zip code",
            "zipcode", "plz", "postleitzahl", "codigo postal", "code postal",
        },
        [FieldGroup.Country] = new[] { "country", "country-name", "land", "staat", "pais", "pays" },

        [FieldGroup.Ssn] = new[]
        {
            "ssn", "social security", "social security number",
            "sozialversicherungsnummer", "sv-nummer",
        },
        [FieldGroup.Passport] = new[]
        {
            "passport", "passport number", "reisepass", "passnummer", "ausweisnummer",
        },
        [FieldGroup.License] = new[]
        {
            "license", "licence", "license number", "driver license", "drivers license",
            "driving licence", "fuehrerschein", "fuhrerschein", "fuehrerscheinnummer",
        },
    };

    // Format hints rather than field names. They turn up inside labels like
    // "Geburtsdatum (DD.MM.YYYY)", so they may only count when they are the entire label - as a
    // partial match they would claim a date of birth box for the card expiry.
    private static readonly HashSet<string> ExactOnlyAliases = new(StringComparer.Ordinal)
    {
        "mm", "yy", "yyyy", "dd", "jj", "jjjj", "tt", "aa", "aaaa",
    };

    public static bool IsExactOnly(string alias) => ExactOnlyAliases.Contains(alias);

    // The normalised lookup table, built once. Field classification walks every group for every
    // input field of a form, so normalising the builtin lists on each access would mean tens of
    // thousands of throwaway allocations in the middle of a typing run.
    private static Dictionary<FieldGroup, string[]> _spellings = BuildSpellings(null);

    // Rebuild the table with the user's additional spellings from config.json merged in.
    public static void Configure(Dictionary<string, List<string>>? userAliases)
        => _spellings = BuildSpellings(userAliases);

    private static Dictionary<FieldGroup, string[]> BuildSpellings(Dictionary<string, List<string>>? userAliases)
    {
        var table = new Dictionary<FieldGroup, string[]>();
        foreach (var (group, words) in Builtin)
            table[group] = Clean(words);

        if (userAliases != null)
        {
            foreach (var (name, words) in userAliases)
            {
                if (!Enum.TryParse<FieldGroup>(name, ignoreCase: true, out var g) || g == FieldGroup.None) continue;
                var extra = Clean(words);
                table[g] = table.TryGetValue(g, out var builtin) ? builtin.Concat(extra).Distinct().ToArray() : extra;
            }
        }
        return table;
    }

    private static string[] Clean(IEnumerable<string> words)
        => words.Select(Normalize).Where(w => w.Length > 0).Distinct().ToArray();

    // Every spelling registered for a group (builtin plus user-supplied), normalised.
    public static IReadOnlyList<string> Spellings(FieldGroup group)
        => _spellings.TryGetValue(group, out var v) ? v : Array.Empty<string>();

    // Resolve whatever the user wrote in {FIELD "..."} to a group. An unknown term yields None,
    // and the caller then searches for that literal term instead.
    public static FieldGroup Resolve(string term)
    {
        string needle = Normalize(term);
        if (needle.Length == 0) return FieldGroup.None;

        if (Enum.TryParse<FieldGroup>(term.Trim(), ignoreCase: true, out var direct) && direct != FieldGroup.None)
            return direct;

        foreach (FieldGroup g in Enum.GetValues<FieldGroup>())
        {
            if (g == FieldGroup.None) continue;
            foreach (var w in Spellings(g))
                if (w == needle) return g;
        }
        return FieldGroup.None;
    }

    // Lowercase, fold umlauts, split camelCase and collapse every separator to a single space, so
    // "E-Mail-Adresse", "email address", "emailAddress" and "Straße" / "Strasse" all reduce to
    // something comparable. Acronyms stay intact: "CVV" must not become "c vv".
    public static string Normalize(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new System.Text.StringBuilder(s.Length + 4);
        bool lastSpace = true;   // leading separators are dropped
        char prev = '\0';
        foreach (char raw in s)
        {
            if (char.IsLetterOrDigit(raw))
            {
                // "cardNumber" -> "card number", but only after a lowercase letter or a digit, so
                // runs of capitals are left alone.
                if (char.IsUpper(raw) && !lastSpace && (char.IsLower(prev) || char.IsDigit(prev)))
                    sb.Append(' ');
                sb.Append(Fold(char.ToLowerInvariant(raw)));
                lastSpace = false;
            }
            else if (!lastSpace)
            {
                sb.Append(' ');
                lastSpace = true;
            }
            prev = raw;
        }
        return sb.ToString().TrimEnd();
    }

    // Fold the accented characters that show up in the languages we ship, so a form spelling a
    // label with umlauts matches an alias written without them.
    private static string Fold(char c) => c switch
    {
        'ä' => "a", 'ö' => "o", 'ü' => "u", 'ß' => "ss",
        'á' or 'à' or 'â' or 'ã' or 'å' => "a",
        'é' or 'è' or 'ê' or 'ë' => "e",
        'í' or 'ì' or 'î' or 'ï' => "i",
        'ó' or 'ò' or 'ô' or 'õ' => "o",
        'ú' or 'ù' or 'û' => "u",
        'ç' => "c", 'ñ' => "n",
        _ => c.ToString(),
    };
}
