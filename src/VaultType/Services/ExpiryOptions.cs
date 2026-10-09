namespace VaultType.Services;

// Decides whether an entry of an expiry drop-down stands for a given month or year. Checkouts word
// these entries in every possible way - "7", "07", "07 - Jul", "July", "Juli (07)", "2029", "29" -
// so the entry is split into words and each word is compared as a number or as a month name.
public static class ExpiryOptions
{
    // Month names and abbreviations in the languages the app ships, normalised the same way field
    // labels are (lowercase, accents folded). Index 0 is January.
    private static readonly string[][] MonthNames =
    {
        new[] { "january", "jan", "januar", "janvier", "janv", "enero", "ene", "gennaio", "gen", "januari", "styczen", "sty", "janeiro" },
        new[] { "february", "feb", "februar", "fevrier", "fevr", "fev", "febrero", "febbraio", "februari", "luty", "lut", "fevereiro" },
        new[] { "march", "mar", "marz", "maerz", "mars", "marzo", "maart", "mrt", "marzec", "marco" },
        new[] { "april", "apr", "avril", "avr", "abril", "abr", "aprile", "kwiecien", "kwi" },
        new[] { "may", "mai", "mayo", "maggio", "mag", "mei", "maj", "maio" },
        new[] { "june", "jun", "juni", "juin", "junio", "giugno", "giu", "czerwiec", "cze", "junho" },
        new[] { "july", "jul", "juli", "juillet", "juil", "julio", "luglio", "lug", "lipiec", "lip", "julho" },
        new[] { "august", "aug", "aout", "agosto", "ago", "augustus", "sierpien", "sie" },
        new[] { "september", "sep", "sept", "septembre", "septiembre", "setiembre", "settembre", "set", "wrzesien", "wrz", "setembro" },
        new[] { "october", "oct", "okt", "oktober", "octobre", "octubre", "ottobre", "ott", "pazdziernik", "paz", "outubro", "out" },
        new[] { "november", "nov", "novembre", "noviembre", "listopad", "lis", "novembro" },
        new[] { "december", "dec", "dez", "dezember", "decembre", "diciembre", "dic", "dicembre", "grudzien", "gru", "dezembro" },
    };

    public static bool MonthMatches(string entry, int month)
    {
        if (month < 1 || month > 12) return false;
        foreach (string word in Words(entry))
        {
            if (int.TryParse(word, out int n))
            {
                // Only one- or two-digit numbers are month numbers; "2029" in the same entry isn't.
                if (word.Length <= 2 && n == month) return true;
            }
            else if (Array.IndexOf(MonthNames[month - 1], word) >= 0) return true;
        }
        return false;
    }

    public static bool YearMatches(string entry, int year)
    {
        if (year < 2000 || year > 2099) return false;
        foreach (string word in Words(entry))
        {
            if (!int.TryParse(word, out int n)) continue;
            if (word.Length == 4 && n == year) return true;
            if (word.Length == 2 && n == year % 100) return true;
        }
        return false;
    }

    private static string[] Words(string entry)
        => FieldAliases.Normalize(entry).Split(' ', StringSplitOptions.RemoveEmptyEntries);
}
