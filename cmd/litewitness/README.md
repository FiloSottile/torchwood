# litewitness

litewitness is a synchronous low-latency cosigning witness. (A witness is a
service that accepts a new signed tree head, checks its consistency with the
previous latest tree head, and returns a signature over it.) It implements the
[c2sp.org/tlog-witness](https://c2sp.org/tlog-witness) protocol.

It's backed by a SQLite database for storage, and by an ssh-agent for private
key operations.

To install it, use `go install`.

```
# from anywhere
go install filippo.io/torchwood/cmd/{litewitness,witnessctl}@latest

# from within a source tree
go install filippo.io/torchwood/cmd/{litewitness,witnessctl}
```

litewitness has no config file. All configuration is done via command line flags
or `witnessctl` (see below).

    -db string
            path to sqlite database (default "litewitness.db")

The SQLite database is where known trees and tree heads are stored. It needs to
be on a filesystem that supports locking (not a network file system). It will be
created if it does not exist.

    -name string
            URL-like (e.g. example.com/foo) name of this witness

The name of the witness is a URL-like value that will appear in cosignature
lines. It does not need to be where the witness is reachable but should be
recognizable.

    -key string
            SSH fingerprint (with SHA256: prefix) of the witness key
    -ssh-agent string
            path to ssh-agent socket (default "litewitness.sock")

The witness Ed25519 private key is provided by a ssh-agent instance. The socket
is specified explicitly because it's recommended that a dedicated instance is
run for litewitness. The use of the ssh-agent protocol allows the key to be
provided by a key file, a PKCS#11 module, or custom hardware agents.

Example of starting a dedicated ssh-agent and loading a key:

```
ssh-agent -a litewitness.sock
SSH_AUTH_SOCK=litewitness.sock ssh-add litewitness.pem
```

    -bastion string
            address of the bastion(s) to reverse proxy through, comma separated, the first online one is selected
    -listen string
            address to listen for HTTP requests (default "localhost:7380")

Only one of `-bastion` or `-listen` must be specified. The former will cause
litewitness to serve requests through a bastion reverse proxy (see below). The
latter will listen for HTTP requests on the specified port. (HTTPS needs to be
terminated outside of litewitness.) The bastion flag is an optionally
comma-separated list of bastions to try in order until one connects
successfully. If the connection drops after establishing, litewitness exits.

## witnessctl

witnessctl is a CLI tool to operate on the litewitness database. It can be used
while litewitness is running.

    witnessctl add-log -db <path> -origin <origin>

The `add-log` command adds a new known log starting at a size of zero. Removing
a log is not supported, as it presents the risk of signing a split view if
re-added. To disable a log, remove all its keys.

    witnessctl add-key -db <path> -origin <origin> -key <verifier key>
    witnessctl del-key -db <path> -origin <origin> -key <verifier key>

The `add-key` and `del-key` commands add and remove verifier keys for a known
log. The name of the key must match the log origin.

    witnessctl add-sigsum-log -db <path> -key <hex-encoded key>

The `add-sigsum-log` command is a helper that adds a new Sigsum log, computing
the origin and key from a 32-byte hex-encoded Ed25519 public key.

    witnessctl list-logs -db <path>

The `pull-logs` command fetches a list of known logs from [a witness network log
list](https://github.com/transparency-dev/witness-network/blob/main/site/content/participate.md#automate-discovery-of-logs-in-the-selected-lists)
URL or file path. It only adds new logs, it does not remove or change the keys
of existing ones. It is designed to run in a cronjob, and by default (without
`-verbose`) it only prints output if there are logs with keys different from
what is already in the database. This is unexpected and manual investigation as
to why the log list changed (or disagrees with manual configuration) is needed.

    witnessctl pull-logs -db <path> -source <log list url> -verbose

The `list-logs` command lists known logs, in JSON lines like the following.

    {"origin":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562","size":5,"root_hash":"QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=","keys":["sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562+5202289b+Af/cLU2Y5BJNP+r3iMDC+av9eWCD0fBJVDfzAux5zxAP"]}
