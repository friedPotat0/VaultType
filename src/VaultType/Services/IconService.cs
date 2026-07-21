using System.IO;
using System.Net.Http;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace VaultType.Services;

// Pulls real favicons from the user's own Vaultwarden (/icons/<domain>/icon.png). Nothing
// third-party is contacted - that server already knows the domains anyway. Cached on disk and
// in memory. Turn it off in the config to stay fully offline (letter avatars).
public sealed class IconService : IDisposable
{
    private const long MaxIconBytes = 512 * 1024;   // hard cap on any downloaded or cached icon

    private readonly bool _enabled;
    private readonly string _base;
    private readonly string _cacheDir;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(6) };
    private readonly Dictionary<string, ImageSource?> _mem = new(StringComparer.OrdinalIgnoreCase);

    public IconService(string serverUrl, bool showIcons, string cacheDir)
    {
        _enabled = showIcons && !string.IsNullOrWhiteSpace(serverUrl);
        _base = (serverUrl ?? "").TrimEnd('/');
        _cacheDir = cacheDir;
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
            if (File.Exists(file))
            {
                // Ignore an oversized cache file rather than reading it all into memory.
                if (new FileInfo(file).Length <= MaxIconBytes) bytes = await File.ReadAllBytesAsync(file);
            }
            else
            {
                // domain is escaped so it can only ever be a single path segment, and the download
                // is size-capped so a huge or hostile icon can't blow up memory or the cache.
                bytes = await DownloadCappedAsync($"{_base}/icons/{Uri.EscapeDataString(domain)}/icon.png");
                if (bytes is { Length: > 0 }) await File.WriteAllBytesAsync(file, bytes);
            }
        }
        catch { bytes = null; }

        ImageSource? img = bytes is { Length: > 0 } ? LoadBitmap(bytes) : null;
        _mem[domain] = img;
        return img;
    }

    // Streams the response and aborts once it exceeds the cap, so nothing huge is ever
    // buffered fully or written to the on-disk cache.
    private async Task<byte[]?> DownloadCappedAsync(string url)
    {
        using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!resp.IsSuccessStatusCode) return null;
        if (resp.Content.Headers.ContentLength is long declared && declared > MaxIconBytes) return null;

        await using var stream = await resp.Content.ReadAsStreamAsync();
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
        {
            if (ms.Length + read > MaxIconBytes) return null;   // over the cap -> discard, don't cache
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
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

    public void Dispose() => _http.Dispose();
}
