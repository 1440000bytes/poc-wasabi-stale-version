# poc-wasabi-stale-version

Wasabi's update path will download, verify, and stage for install a genuinely
Wasabi-signed release that is **older than the latest** (stale-version pinning /
update suppression).

`poc-nostr-forgery` proved the client ACCEPTS an unauthenticated announcement. This repo
shows the payoff for the one asset class the installer signature gate does not stop: a
real, Wasabi-signed release that is not the newest one. If an announcement names a real
release `V` and points at the authentic GitHub assets for `V`, the production
`ReleaseDownloader` verifies the genuine `SHA256SUMS.wasabisig` against the hardcoded
`WasabiPubKey`, matches the installer hash, and stages `V`. On exit
`WalletWasabi.Fluent.Desktop/Program.cs` runs it through `Installer.StartInstallingNewVersion`
when `DownloadNewVersion` is on (the default).

## This is not a rollback of the running binary

`UpdateManager` only accepts an announced version **greater than the current one**
(`releases.Where(x => x.Version > currentVersion)`), so it can never move a victim below
the version they are running. The demo shows the victim's version going **up**, from
2.6.0 to 2.7.0.

The attack is that 2.7.0 is **not the latest** (2.8.2 is). The attacker pins the victim
onto a stale, genuinely-signed build that sits between the victim's current version and
the latest release, re-exposing everything fixed in `(2.7.0, 2.8.2]` while denying them
the newest update. So the accurate label is stale-version pinning / update suppression to
an older-than-latest signed release, not a downgrade. It only bites a victim who is behind
the release being announced.

## Relationship to the signer-identity fix

The announcement is delivered over Nostr. The originally-reported forgery bug (client
accepted an announcement from ANY signer, see `poc-nostr-forgery`) was fixed in PR #15005
("Verify note author is wasabi team"), shipped in v2.8.2, which drops any event whose
pubkey is not the Wasabi team key.

That fix blocks the forged DELIVERY used here (an attacker key), so at HEAD the pinning
must be delivered by a genuine team announcement, a **replay of an old genuine team note**
(there is no freshness / `created_at` check, and `limit: 1` means the newest delivered
note wins), or team-key compromise. The download / verify / stage chain is identical in
every case and is unaffected by that fix. This PoC targets the same pre-fix commit
`154c4a5` as `poc-nostr-forgery` so the whole chain runs over the wire without the team
key.

Control: the fix's own `WalletWasabi.Tests/UnitTests/WebClients/WasabiNostrClientTests.cs`
(added in 2dbb6ec) checks that a note authored by a non-team key is dropped, so the
identical forged announcement used here is ignored on a post-fix tree.

## How to run

Requires .NET SDK 10 and internet access (the PoC downloads the genuine Wasabi 2.7.0
release assets from GitHub on first run).

1. Check out the audited WalletWasabi at commit `154c4a5` as a sibling directory named
   `WalletWasabi`, next to this repo:

   ```
   git clone https://github.com/WalletWasabi/WalletWasabi
   cd WalletWasabi && git checkout 154c4a5 && cd ..
   ```

   Layout expected by `Poc/Poc.csproj`:

   ```
   <parent>/WalletWasabi/WalletWasabi/WalletWasabi.csproj
   <parent>/poc-wasabi-stale-version/
   ```

2. Run:

   ```
   dotnet run --project FakeRelay   # terminal 1 - malicious relay
   dotnet run --project Poc         # terminal 2 - Wasabi update service, wired as in Global.cs
   ```

## Expected output

```
[POC] victim currentVersion = 2.6.0; running the production updater once...
INF | UpdateManager.cs:78  | New version found: 2.7.0
[POC] NewSoftwareVersionAvailable: version=2.7.0 upToDate=False readyToInstall=False
INF | UpdateManager.cs:135 | Trying to download new version.
INF | UpdateManager.cs:158 | Installer downloaded to: /tmp/wasabi-installer-2.7.0/Wasabi-2.7.0.deb
INF | UpdateManager.cs:164 | Installer verified successfully
[POC] NewSoftwareVersionAvailable: version=2.7.0 upToDate=False readyToInstall=True
[POC] NewSoftwareVersionInstallerAvailable: /tmp/wasabi-installer-2.7.0/Wasabi-2.7.0.deb
[POC] staged 69487660 bytes, sha256 = 91a1e9b21caf317104c1f50a4a0c0e7810d29b221d060fd77274afc690ecaed8
[POC] MATCH: sha256 equals the Wasabi-signed SHA256SUMS entry for Wasabi-2.7.0.deb
```

The victim was on 2.6.0 and is now staged to install 2.7.0 while 2.8.2 is the latest. As an
independent check the PoC re-reads the ECDSA-verified `SHA256SUMS.asc` the client itself
downloaded and confirms the staged `.deb`'s sha256 equals the signed entry for its filename,
so the artifact is provably the genuine Wasabi 2.7.0 build. The production code had already
verified `SHA256SUMS.wasabisig` against the hardcoded `WasabiPubKey` and matched the hash
before staging. The PoC does **not** launch the installer.

## Structure

- `FakeRelay/` — a small NIP-01 WebSocket relay. It answers the client's `REQ` with an
  event validly signed by an ATTACKER key (not the team key), announcing the real 2.7.0
  with every asset URL pointing at the authentic GitHub files.
- `Poc/` — references the audited WalletWasabi (`ProjectReference`, commit `154c4a5`) and
  wires the production `UpdateManager` + `ReleaseDownloader` exactly as
  `WalletWasabi.Client/Global.cs:ConfigureWasabiUpdater` does, with the victim's current
  version set to 2.6.0.

## Suggested fixes

1. Reject an announced version not greater than the latest release the client knows of
   (a version ceiling against the newest release, not just against the running one).
   `UpdateManager` currently accepts any version above the running one.
2. Add announcement freshness (reject stale `created_at`) to blunt replay of old genuine
   notes.
3. (Already shipped in v2.8.2) verify the announcement's signer is the Wasabi team key.
