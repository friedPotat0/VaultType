using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using VaultType.Models;
using VaultType.Security;

namespace VaultType.Services;

// How a typing run ended. Anything but Done means nothing (or only part) was typed, and the caller
// tells the user why rather than leaving them guessing at a half-filled form.
public enum TypeResult { Done, FocusLost, FieldNotFound, NoFieldsDetected }

// MissingField names the field a lookup failed on, so the message can be specific about it.
public readonly record struct TypeOutcome(TypeResult Result, string MissingField)
{
    public static readonly TypeOutcome Done = new(TypeResult.Done, "");
}

// Types keystrokes into the window that was active before. Secrets are decrypted into a locked
// buffer only for the instant we type them and wiped right after - no clipboard involved. If
// focus leaves the target mid-sequence we stop immediately (KeePass-style), so stray characters
// never land in the wrong window.
//
// Cards and identities are placed by label lookup (see FieldFinder) instead of a fixed tab order -
// payment and checkout forms differ far too much for tabbing blindly to be safe.
public static class AutoTyper
{
    private sealed class FocusLost : Exception { }

    private sealed class FieldMissing : Exception
    {
        public readonly string FieldName;
        public FieldMissing(string fieldName) => FieldName = fieldName;
    }

    // Everything one typing run needs, so the field lookup's element cache survives the whole
    // sequence instead of rescanning the tree per field.
    private sealed class Run
    {
        public IntPtr Target;
        public VaultItem Item = null!;
        public SecretProtector Protector = null!;
        public int DelayMs;
        public bool ClearFieldEnabled;
        public bool RequiredOnly;
        public FieldFinder Finder = null!;
    }

    public static TypeOutcome Type(IntPtr target, VaultItem item, SecretProtector protector,
                                   ItemField field, int delayMs, bool clearField, bool requiredOnly)
    {
        var run = new Run
        {
            Target = target,
            Item = item,
            Protector = protector,
            DelayMs = delayMs,
            ClearFieldEnabled = clearField,
            RequiredOnly = requiredOnly,
            Finder = new FieldFinder(target),
        };

        try
        {
            RestoreFocus(target);   // aborts (FocusLost) if the target never comes to the foreground

            if (field != ItemField.None)
            {
                ClearField(run, run.ClearFieldEnabled);
                TypeSingleField(run, field);
                return TypeOutcome.Done;
            }

            if (!string.IsNullOrWhiteSpace(item.CustomSequence))
            {
                RunSequence(run, item.CustomSequence!);
                return TypeOutcome.Done;
            }

            switch (item.Kind)
            {
                case ItemKind.Card: RunCardDefault(run); break;
                case ItemKind.Identity: RunIdentityDefault(run); break;
                default: RunLoginDefault(run); break;
            }
            return TypeOutcome.Done;
        }
        catch (FocusLost) { return new TypeOutcome(TypeResult.FocusLost, ""); }
        catch (FieldMissing ex)
        {
            // Distinguish "this particular field is missing" from "there is nothing here we can
            // fill" - the latter covers both a window that exposes no fields at all and a form
            // whose fields don't line up with this entry.
            if (ex.FieldName.Length == 0 || !run.Finder.AnyFieldsVisible())
                return new TypeOutcome(TypeResult.NoFieldsDetected, "");
            return new TypeOutcome(TypeResult.FieldNotFound, ex.FieldName);
        }
    }

    // ---- default sequences ----

    // Logins keep the classic behaviour: username <Tab> password <Enter>, no field lookup.
    private static void RunLoginDefault(Run run)
    {
        var item = run.Item;
        if (!string.IsNullOrEmpty(item.Username))
        {
            ClearField(run, run.ClearFieldEnabled);
            TypeText(run, item.Username);
            SendVk(run.Target, Native.VK_TAB);
        }
        ClearField(run, run.ClearFieldEnabled);
        TypeSecret(run, item.Password);
        SendVk(run.Target, Native.VK_RETURN);
    }

    // Cards and identities have no fixed field list: the form decides. One checkout wants number,
    // expiry and code, the next also asks for the cardholder; one order form has a single name box,
    // the next three name fields plus an address block. Deliberately without a trailing Enter -
    // submitting a checkout half-filled is destructive in a way a login form isn't.
    private static void RunCardDefault(Run run) => FillDetectedFields(run);

    private static void RunIdentityDefault(Run run) => FillDetectedFields(run);

    private static void FillDetectedFields(Run run)
    {
        var fields = run.Finder.DetectFields();

        // By default only fill what the form insists on, so optional extras stay empty. Forms that
        // mark nothing as mandatory - plenty only validate in JavaScript - would end up with
        // nothing filled at all, so there we fall back to every field we recognise.
        bool anyRequired = fields.Any(f => f.Required);
        var candidates = run.RequiredOnly && anyRequired ? fields.Where(f => f.Required).ToList() : fields;

        // A separate house number field means the street line has to be split; without one the
        // address line goes in whole. Decided over every field, not just the mandatory ones -
        // whether a form splits the address is a property of the form, and plenty mark the street
        // as required while leaving the number optional.
        bool splitStreet = fields.Any(f => f.Group == FieldGroup.HouseNumber)
                           && run.Item.Identity?.Address1 != null;

        var handled = new HashSet<FieldGroup>();
        var usedCustom = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int filled = 0;

        foreach (var field in candidates)
        {
            bool groupUsable = field.Group != FieldGroup.None
                               && !handled.Contains(field.Group)
                               && HasValue(run.Item, field.Group);

            // A custom field the user named themselves competes with the builtin group on equal
            // terms: whichever matched the label more specifically wins. A box labelled
            // "Geburtsdatum (DD.MM.YYYY)" must go to a custom "Geburtsdatum" rather than to the
            // card expiry month that the "MM" inside it would otherwise suggest.
            var custom = MatchCustomField(run.Item, field, usedCustom, out int customLen);
            bool customWins = custom != null && (!groupUsable || customLen > field.GroupMatchLength);

            if (!groupUsable && custom == null) continue;

            // The form may have moved on since the scan; skip what we can no longer focus rather
            // than abandoning the fields further down.
            if (!run.Finder.FocusAt(field)) continue;
            ClearField(run, run.ClearFieldEnabled);

            if (customWins)
            {
                TypeSecret(run, custom!.Value);
                usedCustom.Add(custom.Name);
            }
            else
            {
                TypeGroupValue(run, field.Group, splitStreet);
                handled.Add(field.Group);
                foreach (var c in Conflicts(field.Group)) handled.Add(c);
            }
            filled++;
        }

        // Nothing matched at all: report it instead of leaving the user wondering why the form
        // stayed empty. An empty field name means "nothing here fits this entry" rather than one
        // particular field being absent.
        if (filled == 0) throw new FieldMissing("");
    }

    // A custom field whose name matches this form field's label or id, plus how specific that match
    // was. Exact matches win over partial ones so a "Date of birth" box isn't claimed by a custom
    // field merely called "Date".
    private static CustomField? MatchCustomField(VaultItem item, FieldFinder.DetectedField field,
                                                 HashSet<string> alreadyUsed, out int matchLength)
    {
        CustomField? best = null;
        int bestLen = 0;
        foreach (var cf in item.CustomFields)
        {
            if (cf.Value == null || alreadyUsed.Contains(cf.Name)) continue;
            string name = FieldAliases.Normalize(cf.Name);
            if (name.Length == 0) continue;

            if (field.Label == name || field.Id == name) { matchLength = int.MaxValue; return cf; }
            if (name.Length > bestLen
                && (FieldFinder.ContainsWord(field.Label, name) || FieldFinder.ContainsWord(field.Id, name)))
            {
                best = cf;
                bestLen = name.Length;
            }
        }
        matchLength = bestLen;
        return best;
    }

    // Groups that express the same thing a different way. Once one is filled, its alternatives must
    // not be filled as well - a form offering both a combined "MM/YY" box and separate month/year
    // boxes would otherwise get the expiry twice.
    private static IEnumerable<FieldGroup> Conflicts(FieldGroup group) => group switch
    {
        FieldGroup.FullName => new[] { FieldGroup.FirstName, FieldGroup.LastName },
        FieldGroup.FirstName or FieldGroup.LastName => new[] { FieldGroup.FullName },
        FieldGroup.CardExpiry => new[] { FieldGroup.CardExpMonth, FieldGroup.CardExpYear },
        FieldGroup.CardExpMonth or FieldGroup.CardExpYear => new[] { FieldGroup.CardExpiry },
        FieldGroup.Address1 => new[] { FieldGroup.StreetName },
        FieldGroup.StreetName => new[] { FieldGroup.Address1 },
        _ => Array.Empty<FieldGroup>(),
    };

    private static bool HasValue(VaultItem item, FieldGroup group)
    {
        var card = item.Card;
        var id = item.Identity;
        return group switch
        {
            FieldGroup.CardNumber => card?.Number != null,
            FieldGroup.CardCode => card?.Code != null,
            FieldGroup.CardHolder => !string.IsNullOrEmpty(card?.CardholderName),
            FieldGroup.CardExpMonth => card?.ExpMonth != null,
            FieldGroup.CardExpYear => card?.ExpYear != null,
            FieldGroup.CardExpiry => card?.HasExpiry == true,

            FieldGroup.Title => id?.Title != null,
            FieldGroup.FirstName => !string.IsNullOrEmpty(id?.FirstName),
            FieldGroup.MiddleName => id?.MiddleName != null,
            FieldGroup.LastName => !string.IsNullOrEmpty(id?.LastName),
            FieldGroup.FullName => !string.IsNullOrEmpty(id?.FullName),
            FieldGroup.Company => id?.Company != null,
            FieldGroup.Email => id?.Email != null,
            FieldGroup.Phone => id?.Phone != null,
            FieldGroup.Username => id?.Username != null,
            FieldGroup.Address1 => id?.Address1 != null,
            // Both are served from the single address line the vault stores.
            FieldGroup.StreetName => id?.Address1 != null,
            FieldGroup.HouseNumber => id?.Address1 != null,
            FieldGroup.Address2 => id?.Address2 != null,
            FieldGroup.Address3 => id?.Address3 != null,
            FieldGroup.City => id?.City != null,
            FieldGroup.State => id?.State != null,
            FieldGroup.PostalCode => id?.PostalCode != null,
            FieldGroup.Country => id?.Country != null,
            FieldGroup.Ssn => id?.Ssn != null,
            FieldGroup.Passport => id?.PassportNumber != null,
            FieldGroup.License => id?.LicenseNumber != null,
            _ => false,
        };
    }

    private static void TypeGroupValue(Run run, FieldGroup group, bool splitStreet = false)
    {
        var card = run.Item.Card;
        var id = run.Item.Identity;

        // Street and house number in separate boxes: the address line is split so each part lands
        // where it belongs, instead of "Beispielweg 12" going into the street field as a whole.
        if (splitStreet && group is FieldGroup.Address1 or FieldGroup.StreetName)
        {
            TypeStreetPart(run, id?.Address1, wantNumber: false);
            return;
        }
        if (group == FieldGroup.HouseNumber)
        {
            TypeStreetPart(run, id?.Address1, wantNumber: true);
            return;
        }

        switch (group)
        {
            case FieldGroup.CardNumber: TypeSecret(run, card?.Number); break;
            case FieldGroup.CardCode: TypeSecret(run, card?.Code); break;
            case FieldGroup.CardHolder: TypeText(run, card?.CardholderName ?? ""); break;
            case FieldGroup.CardExpMonth: TypeExpMonth(run, card?.ExpMonth); break;
            case FieldGroup.CardExpYear: TypeSecret(run, card?.ExpYear); break;
            case FieldGroup.CardExpiry:
                TypeExpMonth(run, card?.ExpMonth); TypeText(run, "/"); TypeYearShort(run, card?.ExpYear);
                break;

            case FieldGroup.Title: TypeSecret(run, id?.Title); break;
            case FieldGroup.FirstName: TypeText(run, id?.FirstName ?? ""); break;
            case FieldGroup.MiddleName: TypeSecret(run, id?.MiddleName); break;
            case FieldGroup.LastName: TypeText(run, id?.LastName ?? ""); break;
            case FieldGroup.FullName: TypeText(run, id?.FullName ?? ""); break;
            case FieldGroup.Company: TypeSecret(run, id?.Company); break;
            case FieldGroup.Email: TypeSecret(run, id?.Email); break;
            case FieldGroup.Phone: TypeSecret(run, id?.Phone); break;
            case FieldGroup.Username: TypeSecret(run, id?.Username); break;
            case FieldGroup.Address1: TypeSecret(run, id?.Address1); break;
            case FieldGroup.Address2: TypeSecret(run, id?.Address2); break;
            case FieldGroup.Address3: TypeSecret(run, id?.Address3); break;
            case FieldGroup.City: TypeSecret(run, id?.City); break;
            case FieldGroup.State: TypeSecret(run, id?.State); break;
            case FieldGroup.PostalCode: TypeSecret(run, id?.PostalCode); break;
            case FieldGroup.Country: TypeSecret(run, id?.Country); break;
            case FieldGroup.Ssn: TypeSecret(run, id?.Ssn); break;
            case FieldGroup.Passport: TypeSecret(run, id?.PassportNumber); break;
            case FieldGroup.License: TypeSecret(run, id?.LicenseNumber); break;
        }
    }

    // Runs a custom sequence template, e.g. {USERNAME}{TAB}{PASSWORD}{ENTER}.
    // Anything that isn't a known token is typed literally.
    private static void RunSequence(Run run, string template)
    {
        int i = 0;
        while (i < template.Length)
        {
            if (template[i] == '{')
            {
                int end = template.IndexOf('}', i + 1);
                if (end < 0) { TypeText(run, template.Substring(i)); break; }
                HandleToken(run, template.Substring(i + 1, end - i - 1).Trim());
                i = end + 1;
            }
            else
            {
                int next = template.IndexOf('{', i);
                if (next < 0) next = template.Length;
                TypeText(run, template.Substring(i, next - i));
                i = next;
            }
        }
    }

    private static void HandleToken(Run run, string token)
    {
        if (token.Length == 0) return;
        string name = token, arg = "";
        int sep = token.IndexOfAny(new[] { ' ', '=' });
        if (sep >= 0) { name = token.Substring(0, sep).Trim(); arg = token.Substring(sep + 1).Trim(); }
        arg = Unquote(arg);

        var item = run.Item;
        var card = item.Card;
        var id = item.Identity;

        switch (name.ToUpperInvariant())
        {
            case "FIELD": case "FELD": GoToNamedField(run, arg); break;
            case "TAB": SendVk(run.Target, Native.VK_TAB); break;
            case "ENTER": case "RETURN": SendVk(run.Target, Native.VK_RETURN); break;
            case "SPACE": TypeText(run, " "); break;
            case "CLEARFIELD": ClearField(run, true); break;
            case "DELAY": case "WAIT": case "SLEEP":
                if (int.TryParse(arg, out int ms)) { Guard(run.Target); Thread.Sleep(Math.Clamp(ms, 0, 60000)); }
                break;

            // On an identity these resolve to its own username/e-mail rather than typing nothing.
            case "USERNAME": case "USER": case "LOGIN":
                if (id != null) TypeSecret(run, id.Username); else TypeText(run, item.Username);
                break;
            case "PASSWORD": case "PASS": TypeSecret(run, item.Password); break;
            case "TOTP": case "OTP": TypeTotp(run); break;

            case "CARDNUMBER": case "CARDNUM": TypeSecret(run, card?.Number); break;
            case "CARDCODE": case "CVV": case "CVC": TypeSecret(run, card?.Code); break;
            case "CARDHOLDER": case "CARDNAME": TypeText(run, card?.CardholderName ?? ""); break;
            case "CARDBRAND": TypeText(run, card?.Brand ?? ""); break;
            case "CARDEXPMONTH": case "EXPMONTH": TypeExpMonth(run, card?.ExpMonth); break;
            case "CARDEXPMONTHRAW": TypeSecret(run, card?.ExpMonth); break;
            case "CARDEXPYEAR": case "EXPYEAR": TypeSecret(run, card?.ExpYear); break;
            case "CARDEXPYEAR2": case "EXPYEAR2": TypeYearShort(run, card?.ExpYear); break;
            case "CARDEXP": case "CARDEXPIRY":
                TypeExpMonth(run, card?.ExpMonth); TypeText(run, "/"); TypeYearShort(run, card?.ExpYear);
                break;

            case "TITLE": TypeSecret(run, id?.Title); break;
            case "FIRSTNAME": TypeText(run, id?.FirstName ?? ""); break;
            case "MIDDLENAME": TypeSecret(run, id?.MiddleName); break;
            case "LASTNAME": TypeText(run, id?.LastName ?? ""); break;
            case "FULLNAME": TypeText(run, id?.FullName ?? ""); break;
            case "COMPANY": TypeSecret(run, id?.Company); break;
            case "EMAIL":
                if (id != null) TypeSecret(run, id.Email); else TypeText(run, item.Username);
                break;
            case "PHONE": TypeSecret(run, id?.Phone); break;
            case "ADDRESS": case "ADDRESS1": TypeSecret(run, id?.Address1); break;
            case "ADDRESS2": TypeSecret(run, id?.Address2); break;
            case "ADDRESS3": TypeSecret(run, id?.Address3); break;
            case "CITY": TypeSecret(run, id?.City); break;
            case "STATE": TypeSecret(run, id?.State); break;
            case "POSTALCODE": case "ZIP": TypeSecret(run, id?.PostalCode); break;
            case "COUNTRY": TypeSecret(run, id?.Country); break;
            case "SSN": TypeSecret(run, id?.Ssn); break;
            case "PASSPORT": TypeSecret(run, id?.PassportNumber); break;
            case "LICENSE": TypeSecret(run, id?.LicenseNumber); break;

            default: TypeText(run, "{" + token + "}"); break; // unknown -> literal
        }
    }

    private static string Unquote(string s)
        => s.Length >= 2 && s[0] == '"' && s[^1] == '"' ? s[1..^1] : s;

    private static void TypeSingleField(Run run, ItemField field)
    {
        var item = run.Item;
        var card = item.Card;
        var id = item.Identity;

        switch (field)
        {
            case ItemField.Username: TypeText(run, item.Username); break;
            case ItemField.Password: TypeSecret(run, item.Password); break;
            case ItemField.Totp: TypeTotp(run); break;

            case ItemField.CardNumber: TypeSecret(run, card?.Number); break;
            case ItemField.CardCode: TypeSecret(run, card?.Code); break;
            case ItemField.CardHolder: TypeText(run, card?.CardholderName ?? ""); break;
            case ItemField.CardExpiry:
                TypeExpMonth(run, card?.ExpMonth); TypeText(run, "/"); TypeYearShort(run, card?.ExpYear);
                break;

            case ItemField.IdName: TypeText(run, id?.FullName ?? ""); break;
            case ItemField.IdEmail: TypeSecret(run, id?.Email); break;
            case ItemField.IdPhone: TypeSecret(run, id?.Phone); break;
            case ItemField.IdAddress: TypeAddress(run, id); break;
        }
    }

    // Street, postal code and city. The street goes into the field the user picked; the other two
    // are located by their labels rather than tabbed to blindly - an address block is exactly the
    // place where a stray tab lands in the wrong box.
    private static void TypeAddress(Run run, IdentityData? id)
    {
        if (id == null) return;
        TypeSecret(run, id.Address1);
        if (id.PostalCode != null) { GoToField(run, FieldGroup.PostalCode); TypeSecret(run, id.PostalCode); }
        if (id.City != null) { GoToField(run, FieldGroup.City); TypeSecret(run, id.City); }
    }

    // ---- field lookup ----

    // Move the caret to the field for a group, or abort the run when the form has no such field.
    private static void GoToField(Run run, FieldGroup group)
    {
        Guard(run.Target);
        if (run.Finder.Focus(group, "")) { ClearField(run, run.ClearFieldEnabled); return; }
        throw new FieldMissing(group.ToString());
    }

    // {FIELD "..."}: resolve whatever the user wrote to a group (so "CVV" and "Prüfziffer" behave
    // identically) and fall back to searching for the literal term.
    private static void GoToNamedField(Run run, string term)
    {
        if (term.Length == 0) return;
        Guard(run.Target);
        var group = FieldAliases.Resolve(term);
        if (run.Finder.Focus(group, term)) { ClearField(run, run.ClearFieldEnabled); return; }
        throw new FieldMissing(term);
    }

    // ---- focus handling ----

    // Bring the target window back to the foreground and confirm it actually took focus before
    // we send a single keystroke. SetForegroundWindow can silently fail (foreground lock, the
    // window went away, focus-stealing prevention), so we don't trust its result blindly and we
    // don't just sleep-and-hope: we poll GetForegroundWindow until the switch is confirmed or a
    // short timeout elapses, and abort (FocusLost) rather than risk typing into the wrong window.
    private static void RestoreFocus(IntPtr target)
    {
        if (target == IntPtr.Zero) throw new FocusLost();
        if (Native.GetForegroundWindow() == target) return;

        Native.SetForegroundWindow(target);

        const int timeoutMs = 500, stepMs = 10;
        for (int waited = 0; waited < timeoutMs; waited += stepMs)
        {
            if (Native.GetForegroundWindow() == target) return;
            Thread.Sleep(stepMs);
        }
        throw new FocusLost();
    }

    // bail out the moment the foreground window isn't our target any more
    private static void Guard(IntPtr target)
    {
        if (Native.GetForegroundWindow() != target) throw new FocusLost();
    }

    // ---- typing primitives ----

    private static void TypeText(Run run, string text)
    {
        foreach (char c in text)
        {
            Guard(run.Target);
            SendUnit(c);
            if (run.DelayMs > 0) Thread.Sleep(run.DelayMs);
        }
    }

    private static void TypeSecret(Run run, SecretBox? box)
    {
        if (box == null || !run.Protector.IsActive) return;
        using LockedBuffer plain = run.Protector.Reveal(box);       // UTF-8 plaintext in locked memory
        int byteLen = box.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);          // UTF-16 in locked memory
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        for (int i = 0; i < n; i++)
        {
            Guard(run.Target);                                      // abort if focus left the target
            SendUnit(charSpan[i]);
            if (run.DelayMs > 0) Thread.Sleep(run.DelayMs);
        }
        // 'chars' and 'plain' are zeroed on dispose
    }

    // One half of the stored address line, for forms with separate street and house number boxes.
    // Bitwarden keeps the whole line in one field, so it has to be split here - which happens on the
    // decrypted characters in locked memory, never via a managed string.
    private static void TypeStreetPart(Run run, SecretBox? box, bool wantNumber)
    {
        if (box == null || !run.Protector.IsActive) return;
        using LockedBuffer plain = run.Protector.Reveal(box);
        int byteLen = box.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);
        var text = charSpan.Slice(0, n);

        var (numStart, numLen) = FindHouseNumber(text);

        if (wantNumber)
        {
            if (numLen > 0) TypeSpan(run, text.Slice(numStart, numLen));
            return;
        }

        // No number recognised: the whole line is the street, and the number field stays empty for
        // the user to complete. Better than splitting at a guess.
        if (numLen == 0) { TypeSpan(run, text); return; }

        var street = numStart == 0 ? text.Slice(numLen) : text.Slice(0, numStart);
        TypeSpan(run, Trim(street));
    }

    // Locate the house number inside an address line. German-style addresses put it last
    // ("Beispielweg 12a"), English-style ones first ("12 Main Street"); anything else is left
    // alone rather than split on a guess.
    private static (int Start, int Length) FindHouseNumber(ReadOnlySpan<char> text)
    {
        int offset = 0;
        while (offset < text.Length && char.IsWhiteSpace(text[offset])) offset++;
        var t = Trim(text.Slice(offset));
        if (t.Length == 0) return (0, 0);

        int lastSpace = t.LastIndexOf(' ');
        if (lastSpace >= 0 && lastSpace + 1 < t.Length && char.IsDigit(t[lastSpace + 1]))
            return (offset + lastSpace + 1, t.Length - lastSpace - 1);

        int firstSpace = t.IndexOf(' ');
        if (firstSpace > 0 && char.IsDigit(t[0]))
            return (offset, firstSpace);

        return (0, 0);
    }

    private static ReadOnlySpan<char> Trim(ReadOnlySpan<char> s)
    {
        int start = 0, end = s.Length;
        while (start < end && char.IsWhiteSpace(s[start])) start++;
        while (end > start && (char.IsWhiteSpace(s[end - 1]) || s[end - 1] == ',')) end--;
        return s.Slice(start, end - start);
    }

    private static void TypeSpan(Run run, ReadOnlySpan<char> text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            Guard(run.Target);
            SendUnit(text[i]);
            if (run.DelayMs > 0) Thread.Sleep(run.DelayMs);
        }
    }

    // The expiry month padded to two digits. Bitwarden stores "1" for January while practically
    // every checkout expects "01", so the leading zero is supplied here.
    private static void TypeExpMonth(Run run, SecretBox? box)
    {
        if (box == null || !run.Protector.IsActive) return;
        using LockedBuffer plain = run.Protector.Reveal(box);
        int byteLen = box.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        if (n == 1) { Guard(run.Target); SendUnit('0'); if (run.DelayMs > 0) Thread.Sleep(run.DelayMs); }
        for (int i = 0; i < n; i++)
        {
            Guard(run.Target);
            SendUnit(charSpan[i]);
            if (run.DelayMs > 0) Thread.Sleep(run.DelayMs);
        }
    }

    // The last two digits of the expiry year, for forms that ask for "YY".
    private static void TypeYearShort(Run run, SecretBox? box)
    {
        if (box == null || !run.Protector.IsActive) return;
        using LockedBuffer plain = run.Protector.Reveal(box);
        int byteLen = box.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        int from = n > 2 ? n - 2 : 0;
        for (int i = from; i < n; i++)
        {
            Guard(run.Target);
            SendUnit(charSpan[i]);
            if (run.DelayMs > 0) Thread.Sleep(run.DelayMs);
        }
    }

    private static void TypeTotp(Run run)
    {
        var item = run.Item;
        if (item.TotpSecret == null || !run.Protector.IsActive) return;
        using LockedBuffer plain = run.Protector.Reveal(item.TotpSecret);   // UTF-8 seed in locked memory
        int byteLen = item.TotpSecret.Cipher.Length;

        int charCount = Encoding.UTF8.GetCharCount(plain.Span.Slice(0, byteLen));
        using var chars = new LockedBuffer(charCount * 2);                  // UTF-16 seed, also locked
        var charSpan = MemoryMarshal.Cast<byte, char>(chars.Span);
        int n = Encoding.UTF8.GetChars(plain.Span.Slice(0, byteLen), charSpan);

        string? code = Totp.Compute(charSpan.Slice(0, n));                  // seed never becomes a managed string
        if (code != null) TypeText(run, code);
    }

    // Gap between the individual key events of a modifier combo, in ms.
    private const int ModifierGapMs = 12;

    // Ctrl+A the field first so what we type overwrites whatever was already there. The four events
    // go out one at a time with a gap in between: pushed as a single batch, apps that evaluate the
    // modifier state asynchronously (the Windows 11 Notepad does) can miss the Ctrl and take the A
    // as a literal character, which then leaks into the field instead of selecting it.
    private static void ClearField(Run run, bool enabled)
    {
        if (!enabled) return;
        Guard(run.Target);
        const ushort VK_CONTROL = 0x11, VK_A = 0x41;
        SendKeyEvent(MakeKey(VK_CONTROL, false));
        SendKeyEvent(MakeKey(VK_A, false));
        SendKeyEvent(MakeKey(VK_A, true));
        SendKeyEvent(MakeKey(VK_CONTROL, true));
        Thread.Sleep(25);
    }

    private static void SendKeyEvent(Native.INPUT input)
    {
        var inputs = new[] { input };
        Native.SendInput(1, inputs, Marshal.SizeOf<Native.INPUT>());
        Thread.Sleep(ModifierGapMs);
    }

    // Sends a single UTF-16 code unit as a Unicode keystroke.
    private static void SendUnit(char unit)
    {
        var inputs = new Native.INPUT[2];
        inputs[0].type = Native.INPUT_KEYBOARD;
        inputs[0].u.ki = new Native.KEYBDINPUT { wVk = 0, wScan = unit, dwFlags = Native.KEYEVENTF_UNICODE };
        inputs[1].type = Native.INPUT_KEYBOARD;
        inputs[1].u.ki = new Native.KEYBDINPUT { wVk = 0, wScan = unit, dwFlags = Native.KEYEVENTF_UNICODE | Native.KEYEVENTF_KEYUP };
        Native.SendInput(2, inputs, Marshal.SizeOf<Native.INPUT>());
    }

    private static void SendVk(IntPtr target, ushort vk)
    {
        Guard(target);
        var inputs = new[] { MakeKey(vk, false), MakeKey(vk, true) };
        Native.SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<Native.INPUT>());
    }

    private static Native.INPUT MakeKey(ushort vk, bool keyUp) => new()
    {
        type = Native.INPUT_KEYBOARD,
        u = new Native.INPUTUNION { ki = new Native.KEYBDINPUT { wVk = vk, wScan = 0, dwFlags = keyUp ? Native.KEYEVENTF_KEYUP : 0 } }
    };
}
