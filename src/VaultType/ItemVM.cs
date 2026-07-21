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
    public string Username => Item.Username;
    public bool HasUsername => !string.IsNullOrEmpty(Item.Username);
    public bool HasTotp => Item.HasTotp;
    public bool HasSequence => !string.IsNullOrWhiteSpace(Item.CustomSequence);
    public string Sequence => Item.CustomSequence ?? "";
    public string SequenceHint => Loc.T("picker.seqHint") + "\n" + Sequence;
    public string IconDomain => Item.PrimaryHost;

    // The effective auto-type sequence as coloured tokens (fields green, keys grey, "›" separators),
    // matching the design's inline sequence preview.
    public IReadOnlyList<SeqToken> SequenceTokens => _seqTokens ??= BuildSeqTokens();
    private IReadOnlyList<SeqToken>? _seqTokens;

    private static readonly Brush SeqField = Frozen("#6BA86F");
    private static readonly Brush SeqKey = Frozen("#7D8590");
    private static readonly Brush SeqSep = Frozen("#8A97A3");
    private static readonly Brush SeqDelay = Frozen("#E3B341");

    private List<SeqToken> BuildSeqTokens()
    {
        var parts = new List<SeqToken>();
        void Add(string text, Brush b) { if (parts.Count > 0) parts.Add(new SeqToken("›", SeqSep)); parts.Add(new SeqToken(text, b)); }

        if (HasSequence)
        {
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(Sequence, @"\{[^}]+\}"))
            {
                string up = m.Value[1..^1].Trim().ToUpperInvariant();
                if (up is "USERNAME" or "USER" or "LOGIN") Add("User", SeqField);
                else if (up is "PASSWORD" or "PASS") Add("Pass", SeqField);
                else if (up is "TOTP" or "OTP") Add("TOTP", SeqField);
                else if (up is "TAB") Add("Tab", SeqKey);
                else if (up is "ENTER" or "RETURN") Add("Enter", SeqKey);
                else if (up is "SPACE") Add("Space", SeqKey);
                else if (up.StartsWith("DELAY") || up.StartsWith("WAIT") || up.StartsWith("SLEEP")) Add("Delay", SeqDelay);
                else if (up is "CLEARFIELD") Add("Clear", SeqKey);
            }
            if (parts.Count > 0) return parts;
        }

        // default sequence: user -> tab -> pass -> [tab -> totp ->] enter
        Add("User", SeqField); Add("Tab", SeqKey); Add("Pass", SeqField);
        if (HasTotp) { Add("Tab", SeqKey); Add("TOTP", SeqField); }
        Add("Enter", SeqKey);
        return parts;
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

    public Visibility AvatarVisibility => _icon == null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility IconVisibility => _icon == null ? Visibility.Collapsed : Visibility.Visible;

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
