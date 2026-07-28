using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using VaultType.Models;
using VaultType.Services;
using ColorConverter = System.Windows.Media.ColorConverter;   // vs System.Drawing.ColorConverter

namespace VaultType;

// View model around a VaultItem plus its owning account (for the badge + the right icon
// service / secret protector) and its async-loaded favicon.
public sealed class ItemVM : INotifyPropertyChanged
{
    public VaultItem Item { get; }
    public VaultSession Session { get; }
    private readonly bool _showBadge;

    public ItemVM(VaultItem item, VaultSession session, bool showBadge)
    {
        Item = item;
        Session = session;
        _showBadge = showBadge;
        (BadgeBackground, BadgeForeground) = MakeBadgeBrushes(session.Cfg.ColorHex);
    }

    public string Name => Item.Name;
    public bool HasTotp => Item.HasTotp;

    // Which section of the picker this row belongs to. Set by the picker before binding; the list
    // groups on it, so identities and cards always end up in their own blocks below the logins.
    public string GroupLabel { get; set; } = "";
    public bool HasSequence => !string.IsNullOrWhiteSpace(Item.CustomSequence);
    public string Sequence => Item.CustomSequence ?? "";
    public string IconDomain => Item.PrimaryHost;

    // Second line of the row. Logins show their username, cards the brand plus the last four
    // digits, identities only the person's name - their remaining fields are protected in RAM and
    // never surface in the list.
    public string Subtitle => Item.Kind switch
    {
        ItemKind.Card => CardSubtitle(),
        ItemKind.Identity => Item.Identity?.FullName ?? "",
        _ => Item.Username,
    };

    public bool HasSubtitle => !string.IsNullOrEmpty(Subtitle);

    private string CardSubtitle()
    {
        var c = Item.Card;
        if (c == null) return "";
        string brand = c.Brand.Length > 0 ? c.Brand : Loc.T("field.card");
        return c.Last4.Length > 0 ? $"{brand} · •••• {c.Last4}" : brand;
    }

    // Which of the three tile styles this row uses: a favicon, a letter avatar, or a type icon
    // for cards and identities (neither of which has a website to fetch an icon from).
    public Visibility AvatarVisibility => Item.Kind == ItemKind.Login && _icon == null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility IconVisibility => Item.Kind == ItemKind.Login && _icon != null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CardVisibility => Item.Kind == ItemKind.Card ? Visibility.Visible : Visibility.Collapsed;
    public Visibility IdentityVisibility => Item.Kind == ItemKind.Identity ? Visibility.Visible : Visibility.Collapsed;

    public bool WantsFavicon => Item.Kind == ItemKind.Login;

    // The brand written into the card tile. Short enough to stay legible at tile size; an unknown
    // or absent brand leaves the tile blank rather than guessing.
    public string CardBrandShort => ShortBrand(Item.Card?.Brand ?? "");

    // The card tile is tinted in the brand's familiar colour - a plain outline in that colour, not
    // a reproduction of anyone's logo. The abbreviation stays alongside it because colour alone
    // wouldn't do: Visa and Amex are both blue. Unrecognised brands keep the neutral grey tile.
    public Brush CardAccent => _cardBrushes.Value.fg;
    public Brush CardFill => _cardBrushes.Value.bg;
    public Brush CardBorder => _cardBrushes.Value.border;

    private Lazy<(Brush fg, Brush bg, Brush border)> _cardBrushes
        => _cardBrushesCache ??= new(() => MakeCardBrushes(Item.Card?.Brand ?? ""));
    private Lazy<(Brush fg, Brush bg, Brush border)>? _cardBrushesCache;

    // Lightened brand tones: the official values are mostly too dark to read on the dark surface.
    private static string BrandColor(string brand) => brand.Trim().ToLowerInvariant() switch
    {
        var b when b.Contains("visa") => "#5B8DEF",
        var b when b.Contains("mastercard") || b == "mc" => "#FF7A45",
        var b when b.Contains("american express") || b.Contains("amex") => "#3DBDF0",
        var b when b.Contains("discover") => "#F5A524",
        var b when b.Contains("diners") => "#7DA9E0",
        var b when b.Contains("unionpay") || b.Contains("union pay") => "#E8556B",
        var b when b.Contains("maestro") => "#4FC3E8",
        var b when b.Contains("jcb") => "#6FC77B",
        var b when b.Contains("rupay") => "#8B93F0",
        _ => "",
    };

    private static (Brush fg, Brush bg, Brush border) MakeCardBrushes(string brand)
    {
        string hex = BrandColor(brand);
        if (hex.Length == 0)
        {
            // Neutral tile for "Other" and anything unrecognised.
            var grey = Frozen("#8A97A3");
            return (grey, Frozen("#14FFFFFF"), Frozen("#26FFFFFF"));
        }

        var c = (Color)ColorConverter.ConvertFromString(hex);
        var fg = new SolidColorBrush(c);
        var bg = new SolidColorBrush(Color.FromArgb(0x24, c.R, c.G, c.B));
        var border = new SolidColorBrush(Color.FromArgb(0x59, c.R, c.G, c.B));
        fg.Freeze(); bg.Freeze(); border.Freeze();
        return (fg, bg, border);
    }

    private static string ShortBrand(string brand)
    {
        string b = brand.Trim().ToLowerInvariant();
        if (b.Length == 0) return "";
        if (b.Contains("visa")) return "VISA";
        if (b.Contains("mastercard") || b == "mc") return "MC";
        if (b.Contains("american express") || b.Contains("amex")) return "AMEX";
        if (b.Contains("discover")) return "DISC";
        if (b.Contains("diners")) return "DC";
        if (b.Contains("unionpay") || b.Contains("union pay")) return "UP";
        if (b.Contains("maestro")) return "MAES";
        if (b.Contains("jcb")) return "JCB";
        if (b.Contains("rupay")) return "RUP";
        return "";   // "Other" and anything unrecognised: plain card tile
    }

    // The effective auto-type sequence as coloured tokens (fields green, keys grey, "›" separators),
    // matching the design's inline sequence preview.
    public IReadOnlyList<SeqToken> SequenceTokens => _seqTokens ??= BuildSeqTokens();
    private IReadOnlyList<SeqToken>? _seqTokens;

    private static readonly Brush SeqField = Frozen("#6BA86F");
    private static readonly Brush SeqKey = Frozen("#7D8590");
    private static readonly Brush SeqSep = Frozen("#8A97A3");
    private static readonly Brush SeqDelay = Frozen("#E3B341");
    private static readonly Brush SeqLookup = Frozen("#58A6FF");   // field looked up by its label

    private List<SeqToken> BuildSeqTokens()
    {
        var parts = new List<SeqToken>();
        void Add(string text, Brush b) { if (parts.Count > 0) parts.Add(new SeqToken("›", SeqSep)); parts.Add(new SeqToken(text, b)); }

        if (HasSequence)
        {
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(Sequence, @"\{[^}]+\}"))
            {
                string body = m.Value[1..^1].Trim();
                string up = body.ToUpperInvariant();
                if (up is "USERNAME" or "USER" or "LOGIN") Add("User", SeqField);
                else if (up is "PASSWORD" or "PASS") Add("Pass", SeqField);
                else if (up is "TOTP" or "OTP") Add("TOTP", SeqField);
                else if (up is "TAB") Add("Tab", SeqKey);
                else if (up is "ENTER" or "RETURN") Add("Enter", SeqKey);
                else if (up is "SPACE") Add("Space", SeqKey);
                else if (up.StartsWith("DELAY") || up.StartsWith("WAIT") || up.StartsWith("SLEEP")) Add("Delay", SeqDelay);
                else if (up is "CLEARFIELD") Add("Clear", SeqKey);
                else if (up.StartsWith("FIELD") || up.StartsWith("FELD")) Add("→ " + LookupName(body), SeqLookup);
                else if (up is "CARDNUMBER" or "CARDNUM") Add("Number", SeqField);
                else if (up is "CARDCODE" or "CVV" or "CVC") Add("CVV", SeqField);
                else if (up.StartsWith("CARDEXP") || up.StartsWith("EXPMONTH") || up.StartsWith("EXPYEAR")) Add("Expiry", SeqField);
                else if (up is "CARDHOLDER" or "CARDNAME") Add("Holder", SeqField);
                else if (up is "FIRSTNAME") Add("First", SeqField);
                else if (up is "LASTNAME") Add("Last", SeqField);
                else if (up is "FULLNAME") Add("Name", SeqField);
                else if (up is "EMAIL") Add("Mail", SeqField);
                else if (up is "PHONE") Add("Phone", SeqField);
            }
            if (parts.Count > 0) return parts;
        }

        switch (Item.Kind)
        {
            // Which fields get filled, and in what order, is decided by the form - listing
            // keystrokes here would suggest an order that doesn't exist.
            case ItemKind.Card:
            case ItemKind.Identity:
                Add(Loc.T("picker.seqAutoFill"), SeqField);
                break;

            default:
                // default sequence: user -> tab -> pass -> [tab -> totp ->] enter
                Add("User", SeqField); Add("Tab", SeqKey); Add("Pass", SeqField);
                if (HasTotp) { Add("Tab", SeqKey); Add("TOTP", SeqField); }
                Add("Enter", SeqKey);
                break;
        }
        return parts;
    }

    // The searched-for name out of {FIELD "..."}, without the token name or its quotes.
    private static string LookupName(string body)
    {
        int sep = body.IndexOfAny(new[] { ' ', '=' });
        if (sep < 0) return "?";
        string arg = body[(sep + 1)..].Trim();
        if (arg.Length >= 2 && arg[0] == '"' && arg[^1] == '"') arg = arg[1..^1];
        return arg.Length > 0 ? arg : "?";
    }

    private static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    public string BadgeText => Session.Cfg.Name;
    public Visibility BadgeVisibility => _showBadge && Session.Cfg.Name.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Brush BadgeBackground { get; }
    public Brush BadgeForeground { get; }

    private ImageSource? _icon;
    public ImageSource? Icon
    {
        get => _icon;
        set
        {
            _icon = value;
            Raise(nameof(Icon));
            Raise(nameof(AvatarVisibility));
            Raise(nameof(IconVisibility));
        }
    }

    // A soft tinted pill: the account colour at low opacity behind the colour itself as text.
    private static (Brush bg, Brush fg) MakeBadgeBrushes(string hex)
    {
        Color c;
        try { c = (Color)ColorConverter.ConvertFromString(hex); }
        catch { c = (Color)ColorConverter.ConvertFromString(Config.AccountConfig.DefaultColor); }
        var bg = new SolidColorBrush(Color.FromArgb(0x2A, c.R, c.G, c.B));
        var fg = new SolidColorBrush(c);
        bg.Freeze();
        fg.Freeze();
        return (bg, fg);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}

// One token of the auto-type sequence preview (a field/key name or the "›" separator).
public sealed class SeqToken
{
    public string Text { get; }
    public Brush Brush { get; }
    public SeqToken(string text, Brush brush) { Text = text; Brush = brush; }
}
