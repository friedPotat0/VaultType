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

    // The authority = host[:port], with scheme, path/query/fragment and any user-info stripped.
    private static string Authority(string url)
    {
        string rest = url;
        int scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) rest = rest[(scheme + 3)..];
        int slash = rest.IndexOfAny(new[] { '/', '?', '#' });
        if (slash >= 0) rest = rest[..slash];
        int at = rest.IndexOf('@');
        if (at >= 0) rest = rest[(at + 1)..];
        return rest;
    }

    private static string HostOf(string url)
    {
        string rest = Authority(url);
        int colon = rest.IndexOf(':');
        if (colon >= 0) rest = rest[..colon];
        return rest.ToLowerInvariant();
    }

    // The port from a URL's authority, or "" when none is specified.
    private static string PortOf(string url)
    {
        string rest = Authority(url);
        int colon = rest.IndexOf(':');
        return colon >= 0 ? rest[(colon + 1)..] : "";
    }

    private static readonly string[] MultiPartSld = { "co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "gv" };

    // Deliberately NOT a full Public Suffix List - that list is huge and changes constantly.
    // This is a pragmatic subset of the common multi-label suffixes under which each sub-label is
    // a separate owner, so the simple heuristic below must not collapse them onto one base domain
    // (e.g. foo.github.io and bar.github.io are different sites, not the same "github.io").
    private static readonly string[] KnownPublicSuffixes =
    {
        "github.io", "githubusercontent.com",
        "s3.amazonaws.com", "blogspot.com",
        "herokuapp.com", "azurewebsites.net", "cloudfront.net",
        "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
        "vercel.app", "netlify.app", "onrender.com", "r2.dev",
    };

    private static string BaseDomain(string host)
    {
        var parts = host.Split('.');
        if (parts.Length <= 2) return host;

        // Known multi-label public suffix: keep the single label in front of the suffix, so sites
        // that merely share the suffix stay distinct base domains.
        foreach (var suffix in KnownPublicSuffixes)
        {
            if (host.Length > suffix.Length + 1
                && host[host.Length - suffix.Length - 1] == '.'
                && host.EndsWith(suffix, StringComparison.Ordinal))
            {
                string label = host[..(host.Length - suffix.Length - 1)];
                int lastDot = label.LastIndexOf('.');
                string owner = lastDot >= 0 ? label[(lastDot + 1)..] : label;
                return $"{owner}.{suffix}";
            }
        }

        string tld = parts[^1], sld = parts[^2];
        if (tld.Length == 2 && Array.IndexOf(MultiPartSld, sld) >= 0)
            return $"{parts[^3]}.{sld}.{tld}";
        return $"{sld}.{tld}";
    }

    public static bool UriMatches(ItemUri u, string pageFull, string pageHost, string pageDomain, int defaultMatch)
    {
        switch (u.MatchType ?? defaultMatch)
        {
            case 5: return false;                                            // Never
            // Regex from the user's own vault, but a bad pattern could backtrack forever - cap it.
            case 4: try { return Regex.IsMatch(pageFull, u.Value, RegexOptions.None, TimeSpan.FromMilliseconds(100)); } catch { return false; }
            case 3: return string.Equals(pageFull, u.Value, StringComparison.OrdinalIgnoreCase);
            case 2: return pageFull.StartsWith(u.Value, StringComparison.OrdinalIgnoreCase);
            case 1:
                // Bitwarden's Host match compares the hostname and, when the saved URI specifies
                // a port, the port too. Host stays port-free (it also feeds display/icons); the
                // port is read from the raw URIs, so a saved URI without a port matches any port.
                if (string.IsNullOrEmpty(u.Host) || !string.Equals(pageHost, u.Host, StringComparison.OrdinalIgnoreCase)) return false;
                string wantPort = PortOf(u.Value);
                return wantPort.Length == 0 || string.Equals(wantPort, PortOf(pageFull), StringComparison.Ordinal);
            default: return !string.IsNullOrEmpty(u.Domain) && string.Equals(pageDomain, u.Domain, StringComparison.OrdinalIgnoreCase);
        }
    }

    // entries that match the current foreground context
    public static List<VaultItem> FindMatches(IReadOnlyList<VaultItem> all, ForegroundInfo ctx, int defaultMatch)
    {
        var res = new List<VaultItem>();

        if (!string.IsNullOrEmpty(ctx.Url))
        {
            var (host, domain) = HostDomain(ctx.Url!);
            foreach (var it in all)
                foreach (var u in it.Uris)
                    if (UriMatches(u, ctx.Url!, host, domain, defaultMatch)) { res.Add(it); break; }
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
