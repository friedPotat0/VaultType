using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading;

namespace VaultType.Services;

// Grabs the official Bitwarden CLI on demand, so we never have to ship it ourselves. The
// download comes straight from Bitwarden's own distribution endpoint.
public static class CliBootstrap
{
    public const string DownloadUrl = "https://vault.bitwarden.com/download/?app=cli&platform=windows";

    public readonly record struct DownloadProgress(long BytesRead, long? TotalBytes);

    public static async Task<bool> EnsureAsync(string destExePath,
        IProgress<DownloadProgress>? progress = null, CancellationToken ct = default)
    {
        if (File.Exists(destExePath)) return true;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destExePath)!);

            // A short connect timeout so a firewall silently dropping the connection fails fast
            // instead of hanging for minutes; the overall timeout still covers a slow transfer.
            var handler = new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(30) };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(3) };

            using var resp = await http.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();

            long? total = resp.Content.Headers.ContentLength;
            using var body = await resp.Content.ReadAsStreamAsync(ct);
            using var ms = new MemoryStream(total is > 0 ? (int)total : 32 * 1024 * 1024);
            var buf = new byte[81920];
            long read = 0;
            int n;
            while ((n = await body.ReadAsync(buf, ct)) > 0)
            {
                ms.Write(buf, 0, n);
                read += n;
                progress?.Report(new DownloadProgress(read, total));
            }

            ms.Position = 0;
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.Equals("bw.exe", StringComparison.OrdinalIgnoreCase));
            if (entry == null) return false;

            entry.ExtractToFile(destExePath, overwrite: true);
            return File.Exists(destExePath);
        }
        catch
        {
            return false;   // network error, timeout or cancellation
        }
    }
}
