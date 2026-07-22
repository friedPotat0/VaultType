using System.Net.Http;
using System.Text.Json;

namespace VaultType.Services;

// Manual, user-triggered update check against the GitHub Releases API. Nothing secret is sent -
// it only reads the latest release tag and compares it to the running version.
public static class UpdateService
{
    private const string Repo = "friedPotat0/VaultType";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

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

            bool newer = Version.TryParse(latest, out var lv)
                      && Version.TryParse(currentVersion, out var cv)
                      && lv > cv;
            return new UpdateInfo(newer, latest, url);
        }
        catch
        {
            // e.g. GitHub 403 rate-limit or no network. The caller only sees "no update".
            return null;
        }
    }
}
