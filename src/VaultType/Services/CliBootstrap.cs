using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;

namespace VaultType.Services;

// Grabs the official Bitwarden CLI on demand, so we never have to ship it ourselves. The
// download comes straight from Bitwarden's own distribution endpoint.
public static class CliBootstrap
{
    private const string DownloadUrl = "https://vault.bitwarden.com/download/?app=cli&platform=windows";

    public static async Task<bool> EnsureAsync(string destExePath)
    {
        if (File.Exists(destExePath)) return true;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destExePath)!);

            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            byte[] zipBytes = await http.GetByteArrayAsync(DownloadUrl);

            using var ms = new MemoryStream(zipBytes);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.Equals("bw.exe", StringComparison.OrdinalIgnoreCase));
            if (entry == null) return false;

            entry.ExtractToFile(destExePath, overwrite: true);
            return File.Exists(destExePath);
        }
        catch
        {
            return false;
        }
    }
}
