using System.IO;
using System.Net.Http;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using VaultType.Config;

namespace VaultType.Services;

// Pulls real favicons from the user's own Vaultwarden (/icons/<domain>/icon.png). Nothing
// third-party is contacted - that server already knows the domains anyway. Cached on disk and
// in memory. Turn it off in the config to stay fully offline (letter avatars).
public sealed class IconService
{
    private readonly bool _enabled;
    private readonly string _base;
    private readonly string _cacheDir;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(6) };
    private readonly Dictionary<string, ImageSource?> _mem = new(StringComparer.OrdinalIgnoreCase);

    public IconService(AppConfig cfg)
    {
        _enabled = cfg.ShowIcons && !string.IsNullOrWhiteSpace(cfg.ServerUrl);
        _base = cfg.ServerUrl.TrimEnd('/');
        _cacheDir = Path.Combine(AppConfig.DataDir, "icons");
        try { Directory.CreateDirectory(_cacheDir); } catch { }
    }

    public async Task<ImageSource?> GetAsync(string domain)
    {
        if (!_enabled || string.IsNullOrWhiteSpace(domain)) return null;
        if (_mem.TryGetValue(domain, out var cached)) return cached;

        byte[]? bytes = null;
        string file = Path.Combine(_cacheDir, Sanitize(domain) + ".png");
        try
        {
            if (File.Exists(file)) bytes = await File.ReadAllBytesAsync(file);
            else
            {
                bytes = await _http.GetByteArrayAsync($"{_base}/icons/{domain}/icon.png");
                if (bytes.Length > 0) await File.WriteAllBytesAsync(file, bytes);
            }
        }
        catch { bytes = null; }

        ImageSource? img = bytes is { Length: > 0 } ? LoadBitmap(bytes) : null;
        _mem[domain] = img;
        return img;
    }

    private static ImageSource? LoadBitmap(byte[] data)
    {
        try
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.CreateOptions = BitmapCreateOptions.PreservePixelFormat;
            bi.StreamSource = new MemoryStream(data);
            bi.EndInit();
            bi.Freeze();
            return bi;
        }
        catch { return null; }
    }

    private static string Sanitize(string domain)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) domain = domain.Replace(c, '_');
        return domain;
    }
}
