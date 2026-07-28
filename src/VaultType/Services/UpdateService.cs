using System.Net.Http;
using System.Text.Json;

namespace VaultType.Services;

// Update check against the GitHub Releases API - run manually from the tray menu or the settings,
// and in the background only when the user turned that on. Nothing secret is sent - it only reads
// the latest release tag and compares it to the running version.
public static class UpdateService
{
    private const string Repo = "friedPotat0/VaultType";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    // Fallback target when a remembered result carries no usable release URL.
    public const string ReleasesUrl = $"https://github.com/{Repo}/releases/latest";

    // How long a result counts as current; past that a manual check asks GitHub again.
    public static readonly TimeSpan RecheckAfter = TimeSpan.FromHours(1);

    public sealed record UpdateInfo(bool IsNewer, string LatestVersion, string Url);

    public static async Task<UpdateInfo?> CheckAsync(string currentVersion)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.github.com/repos/{Repo}/releases/latest");
            req.Headers.UserAgent.ParseAdd("VaultType");
            req.Headers.Accept.ParseAdd("application/vnd.github+json");

            using var resp = await Http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            string tag = root.TryGetProperty("tag_name", out var t) ? (t.GetString() ?? "") : "";
            string url = root.TryGetProperty("html_url", out var u) ? (u.GetString() ?? "") : "";

            string latest = tag.TrimStart('v', 'V');
            if (latest.Length == 0) return null;

            return new UpdateInfo(IsNewer(latest, currentVersion), latest, url);
        }
        catch
        {
            // e.g. GitHub 403 rate-limit or no network. The caller only sees "no update".
            return null;
        }
    }

    // Also used to re-check a remembered result after a restart, so an indicator left over from
    // before the update disappears on its own.
    public static bool IsNewer(string? latest, string current)
        => Version.TryParse(latest, out var lv)
        && Version.TryParse(current, out var cv)
        && lv > cv;

    // A release URL is written to config.json and read back later, and ShellExecute would just as
    // happily run a local path or a protocol handler - so anything but an https GitHub address is
    // replaced by the releases page.
    public static string SafeReleaseUrl(string? url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u)
        && u.Scheme == Uri.UriSchemeHttps
        && (u.Host == "github.com" || u.Host.EndsWith(".github.com", StringComparison.Ordinal))
            ? url!
            : ReleasesUrl;
}
