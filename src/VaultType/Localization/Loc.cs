using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;

namespace VaultType;

// Tiny localization helper. Strings come from embedded Localization/<code>.json files; the
// active language is picked once at startup, falling back to English.
public static class Loc
{
    public static readonly (string Code, string Name)[] Languages =
    {
        ("en", "English"), ("de", "Deutsch"), ("es", "Espanol"), ("fr", "Francais"),
        ("it", "Italiano"), ("ja", "日本語"), ("nl", "Nederlands"), ("pl", "Polski"),
        ("pt_BR", "Portugues (Brasil)"), ("ru", "Русский"), ("zh_CN", "简体中文"),
    };

    private static Dictionary<string, string> _current = new();
    private static Dictionary<string, string> _fallback = new();

    public static void Init(string configLang)
    {
        _fallback = Load("en");
        _current = Load(Resolve(configLang));
    }

    public static string T(string key)
        => _current.TryGetValue(key, out var v) ? v
         : _fallback.TryGetValue(key, out var f) ? f : key;

    public static string T(string key, params object[] args)
    {
        string t = T(key);
        try { return string.Format(t, args); } catch { return t; }
    }

    private static string Resolve(string cfg)
    {
        string code = string.IsNullOrWhiteSpace(cfg) || cfg.Equals("auto", StringComparison.OrdinalIgnoreCase)
            ? MapCulture(CultureInfo.CurrentUICulture)
            : cfg;
        foreach (var l in Languages)
            if (l.Code.Equals(code, StringComparison.OrdinalIgnoreCase)) return l.Code;
        return "en";
    }

    private static string MapCulture(CultureInfo ci)
    {
        string two = ci.TwoLetterISOLanguageName.ToLowerInvariant();
        return two switch { "zh" => "zh_CN", "pt" => "pt_BR", _ => two };
    }

    private static Dictionary<string, string> Load(string code)
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var s = asm.GetManifestResourceStream($"VaultType.Localization.{code}.json");
            if (s == null) return new();
            using var reader = new StreamReader(s);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(reader.ReadToEnd()) ?? new();
        }
        catch { return new(); }
    }
}
