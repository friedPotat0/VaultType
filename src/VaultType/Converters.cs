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

// Stable per-name avatar colour, same idea as Bitwarden's letter avatars. The design's vivid palette.
public static class AvatarPalette
{
    public static readonly Color[] Colours =
    {
        Color.FromRgb(0xA3,0x71,0xF7), Color.FromRgb(0x2E,0xA0,0x43), Color.FromRgb(0x1A,0xBC,0x9C),
        Color.FromRgb(0xE5,0x48,0x6F), Color.FromRgb(0xE0,0x8E,0x0B), Color.FromRgb(0x3D,0x7F,0xC0),
        Color.FromRgb(0x6B,0x7B,0xFF), Color.FromRgb(0x8A,0xA6,0x4A),
    };

    public static Color For(string? name)
    {
        var s = name ?? "";
        int h = 0;
        foreach (char ch in s) h = (h * 31 + ch) & 0x7fffffff;
        return Colours[h % Colours.Length];
    }

    // A top-left-light to bottom-right-dark gradient, like the design avatars.
    public static Brush Gradient(Color c)
    {
        var dark = Color.FromRgb((byte)(c.R * 0.62), (byte)(c.G * 0.62), (byte)(c.B * 0.62));
        return new LinearGradientBrush(c, dark, new System.Windows.Point(0.12, 0), new System.Windows.Point(0.88, 1));
    }
}

public sealed class AvatarBrushConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => new SolidColorBrush(AvatarPalette.For(value as string));
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

// Gradient variant used for the letter avatars (matches the design).
public sealed class AvatarGradientBrushConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => AvatarPalette.Gradient(AvatarPalette.For(value as string));
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}
