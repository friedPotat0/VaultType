using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace VaultType;

// First letter of the name, for the avatar circle.
public sealed class InitialConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        var s = (value as string ?? "").Trim();
        return s.Length > 0 ? char.ToUpperInvariant(s[0]).ToString() : "?";
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

// Stable per-name avatar colour, same idea as Bitwarden's letter avatars.
public sealed class AvatarBrushConverter : IValueConverter
{
    private static readonly Color[] Palette =
    {
        Color.FromRgb(0x17,0x5D,0xDC), Color.FromRgb(0x00,0x9E,0x74), Color.FromRgb(0xB3,0x5A,0x00),
        Color.FromRgb(0x8B,0x3F,0xD6), Color.FromRgb(0xC0,0x37,0x5B), Color.FromRgb(0x0E,0x86,0x9E),
        Color.FromRgb(0xB0,0x8A,0x00), Color.FromRgb(0x4A,0x6B,0x2A),
    };

    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        var s = value as string ?? "";
        int h = 0;
        foreach (char ch in s) h = (h * 31 + ch) & 0x7fffffff;
        return new SolidColorBrush(Palette[h % Palette.Length]);
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}
