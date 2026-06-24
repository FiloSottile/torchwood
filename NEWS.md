## Unreleased

- Dependencies were upgraded.

### torchwood

- Added `SubtreeHash`, `ValidSubtree`, `CoverInterval`, and subtree proofs.

- Added ML-DSA-44 cosignature support.

### mpt

- New package with a Merkle Patricia Trie implementation.

### litewitness

- The `-bastion` flag was removed. Configure per-log bastions instead, for
  example with the new `set-bastions` witnessctl command.

- Added Prometheus metrics and `-listen-metrics` flag.

- The bastion certificate is now generated once at startup.

### witnessctl

- Added `set-bastions` command, which adds the given bastion(s) to every log
  that has none configured (for example after `pull-logs`), or replaces the
  bastions of every log with `-all`.

### litebastion

- Comments and empty lines are now allowed in the backends file.

## v0.9.0

### torchwood

- Added `FormatProof`, `FormatProofWithExtraData` and `ProofExtraData` to format
  [c2sp.org/tlog-proof@v1][] inclusion proofs ("spicy signatures").

- Added `Policy` interface and `VerifyProof`/`VerifyCheckpoint` to verify
  proofs and checkpoints against a configurable (co)signature policy.

- Added `ParsePolicy` to parse policies from a format based on the Sigsum
  textual policies, but using vkeys instead of raw public keys.

[c2sp.org/tlog-proof@v1]: https://c2sp.org/tlog-proof

### tesserax

- New package with a `TileReader` adapter for `tessera.LogReader`.

### litebastion

- `-listen-http` now accepts `host:port` in addition to a bare port number.

- ACME now works correctly when using `-listen-http`.

- Added `-tls-cert` and `-tls-key` flags to use a provided TLS certificate
  instead of ACME. `-testcert` was removed.

- The backends file is now allowed to be empty.

- Added `-obscurity` flag to disable the `/logz` endpoint.

### litewitness

- Added `-obscurity` flag to disable the `/` and `/logz` endpoints.

### witnessctl

- `add-key` now rejects duplicate keys.

- `list-logs` no longer shows duplicate keys and bastions.

### age-keyserver

- Added new tlog demo implementing an age keyserver (see
  https://words.filippo.io/keyserver-tlog/).

## v0.8.0

### torchwood

- Added `TileFS`, a `TileReader` implementation that reads tiles from a
  filesystem. Supports optional gzip decompression of data tiles.

- Added `TileArchiveFS`, an `fs.FS` implementation that reads files from a
  set of zip archives.

## v0.7.0

Updated golang.org/x/... dependencies.

### torchwood

- Added `NewCosignatureVerifier` to parse tlog-cosignature vkeys.

- Added `Client.AllEntries` to fetch all entries from a log without stopping at
  the last full tile boundary. This is useful for one-shot monitors that don't
  tail the log.

### litewitness

- Added support for per-log bastions and `-no-listen` flag. Use the new
  `add-bastion` and `del-bastion` witnessctl commands to manage them.

### litebastion

- Added `-listen-http` flag to accept requests on localhost instead of the
  public port witnesses use to connect to the bastion.

## v0.6.1

### torchwood

- Fix `CosignatureSigner`/`CosignatureVerifier` to correctly sign and verify
  checkpoints with extension lines, according to c2sp.org/tlog-cosignature.

## v0.6.0

Switched to Go project LICENSE (BSD-3-Clause).

Updated minimum Go version to Go 1.24.

### torchwood

- Added tlog client, tiles fetcher, and permanent cache.

- Added `HashProof` to prove inclusion of arbitrary tree interior nodes.

- Added `ReadTileEntry` and `AppendTileEntry` to read and write entry bundles,
  and `ReadSumDBEntry` to read Go sumdb entries.

### litewitness

- Switched to zombiezen.com/go/sqlite.

### witnessctl

- Added `pull-logs` command to fetch logs from the witness network.

### prefix

- New *experimental* prefix trie implementation. Unstable.

## v0.5.0

Renamed repository to Torchwood.

### torchwood

- Exposed various [c2sp.org/signed-note][], [c2sp.org/tlog-cosignature][],
  [c2sp.org/tlog-checkpoint][], and [c2sp.org/tlog-tiles][] functions.

[c2sp.org/signed-note]: https://c2sp.org/signed-note
[c2sp.org/tlog-cosignature]: https://c2sp.org/tlog-cosignature
[c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[c2sp.org/tlog-tiles]: https://c2sp.org/tlog-tiles

## v0.4.3

### litewitness

- Fixed SQLite concurrency issue.

- Redacted IP addresses from `/logz`.

### witnessctl

- Allow verifier keys that don't match the origin, like the Go sumdb's.

### litebastion

- Redacted IP addresses from `/logz`.

## v0.4.2

### litewitness

- Fixed vkey encoding in logs and home page.

- Improved `/logz` web page.

### litebastion

- Improved `/logz` web page.

## v0.4.1

### litebastion

- Fixed formatting of backend key hashes in logs.

## v0.4.0

### litebastion

- Backend connection lifecycle events (including new details about errors) are
  now logged at the INFO level (the default). Client-side errors and HTTP/2
  debug logs are now logged at the DEBUG level.

- `Config.Log` is now a `log/slog.Logger` instead of a `log.Logger`.

- `/logz` now exposes the debug logs in a simple public web console. At most ten
  clients can connect to it at a time.

- New `-home-redirect` flag redirects the root to the given URL.

- Connections to removed backends are now closed on SIGHUP, using the new
  `Bastion.FlushBackendConnections` method.

### litewitness

- `/logz` now exposes the debug logs in a simple public web console. At most ten
  clients can connect to it at a time.

## v0.3.0

### litewitness

- Reduced Info log level verbosity, increased Debug log level verbosity.

- Sending SIGUSR1 (`killall -USR1 litewitness`) will toggle log level between
  Info and Debug.

- `-key` is now an SSH fingerprint (with `SHA256:` prefix) as printed by
  `ssh-add -l`. The old format is still accepted for compatibility.

- The verifier key of the witness is logged on startup.

- A small homepage listing the verifier key and the known logs is served at /.

### witnessctl

- New `add-key` and `del-key` commands.

- `add-log -key` was removed. The key is now added with `add-key`.

## v0.2.1

### litewitness

- Fix cosignature endianness. https://github.com/FiloSottile/litetlog/issues/12
