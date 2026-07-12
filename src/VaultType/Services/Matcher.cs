using System.Text.RegularExpressions;
using VaultType.Models;

namespace VaultType.Services;

// Matches vault entries against the active window/URL using Bitwarden's match rules.
public static class Matcher
{
    public static void FillHostDomain(ItemUri u)
    {
        var (host, domain) = HostDomain(u.Value);
        u.Host = host;
        u.Domain = domain;
    }

    public static (string host, string domain) HostDomain(string url)
    {
        string h = HostOf(url);
        return (h, BaseDomain(h));
    }

    private static string HostOf(string url)
    {
        string rest = url;
        int scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) rest = rest[(scheme + 3)..];
        int slash = rest.IndexOfAny(new[] { '/', '?', '#' });
        if (slash >= 0) rest = rest[..slash];
        int at = rest.IndexOf('@');
        if (at >= 0) rest = rest[(at + 1)..];
        int colon = rest.IndexOf(':');
        if (colon >= 0) rest = rest[..colon];
        return rest.ToLowerInvariant();
    }

    private static readonly string[] MultiPartSld = { "co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "gv" };

    private static string BaseDomain(string host)
    {
        var parts = host.Split('.');
        if (parts.Length <= 2) return host;
        string tld = parts[^1], sld = parts[^2];
        if (tld.Length == 2 && Array.IndexOf(MultiPartSld, sld) >= 0)
            return $"{parts[^3]}.{sld}.{tld}";
        return $"{sld}.{tld}";
    }

    public static bool UriMatches(ItemUri u, string pageFull, string pageHost, string pageDomain)
    {
        switch (u.MatchType)
        {
            case 5: return false;                                            // Never
            // Regex from the user's own vault, but a bad pattern could backtrack forever - cap it.
            case 4: try { return Regex.IsMatch(pageFull, u.Value, RegexOptions.None, TimeSpan.FromMilliseconds(100)); } catch { return false; }
            case 3: return string.Equals(pageFull, u.Value, StringComparison.OrdinalIgnoreCase);
            case 2: return pageFull.StartsWith(u.Value, StringComparison.OrdinalIgnoreCase);
            case 1: return !string.IsNullOrEmpty(u.Host) && string.Equals(pageHost, u.Host, StringComparison.OrdinalIgnoreCase);
            default: return !string.IsNullOrEmpty(u.Domain) && string.Equals(pageDomain, u.Domain, StringComparison.OrdinalIgnoreCase);
        }
    }

    // entries that match the current foreground context
    public static List<VaultItem> FindMatches(IReadOnlyList<VaultItem> all, ForegroundInfo ctx)
    {
        var res = new List<VaultItem>();

        if (!string.IsNullOrEmpty(ctx.Url))
        {
            var (host, domain) = HostDomain(ctx.Url!);
            foreach (var it in all)
                foreach (var u in it.Uris)
                    if (UriMatches(u, ctx.Url!, host, domain)) { res.Add(it); break; }
            return res;
        }

        // No browser URL -> desktop app: match by app://exe, *.exe or title:
        string exe = ctx.Exe;
        string exeNoExt = exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe[..^4] : exe;
        foreach (var it in all)
            foreach (var u in it.Uris)
            {
                var v = u.Value;
                bool m = false;
                if (v.StartsWith("app://", StringComparison.OrdinalIgnoreCase))
                {
                    var target = v[6..];
                    m = string.Equals(target, exe, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(target, exeNoExt, StringComparison.OrdinalIgnoreCase);
                }
                else if (v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    m = string.Equals(v, exe, StringComparison.OrdinalIgnoreCase);
                else if (v.StartsWith("title:", StringComparison.OrdinalIgnoreCase))
                    m = ctx.Title.Contains(v[6..], StringComparison.OrdinalIgnoreCase);

                if (m) { res.Add(it); break; }
            }
        return res;
    }
}
