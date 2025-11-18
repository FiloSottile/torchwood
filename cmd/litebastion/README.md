# litebastion

litebastion is a public-service reverse proxy for witnesses that can't be
exposed directly to the internet.

In short, a witness connects to a bastion over TLS with a Ed25519 client
certificate, "reverses" the direction of the connection, and serves HTTP/2
requests over that connection. The bastion then proxies requests received at
`/<hex-encoded hash of Ed25519 key>/*` to that witness.

    -backends string
            file of accepted key hashes, one per line, reloaded on SIGHUP

The only configuration file of litebastion is the backends file, which lists the
acceptable client/witness key hashes.

    -listen string
            host and port to listen at (default "localhost:8443")
    -cache string
            directory to cache ACME certificates at
    -email string
            email address to register the ACME account with
    -host string
            host to obtain ACME certificate for

If you intend to protect backends from unwanted traffic and not forward
arbitrary requests from the internet, you can accept request on localhost.
This is for example useful when running a bastion for your own log.

    -listen-http PORT
            only accept HTTP requests at http://127.0.0.1:PORT

Since litebastion needs to operate at a lower level than HTTPS on the witness
side, it can't be behind a reverse proxy, and needs to configure its own TLS
certificate. Use the `-cache`, `-email`, and `-host` flags to configure the ACME
client. The ALPN ACME challenge is used, so as long as the `-listen` port
receives connections to the `-host` name at port 443, everything should just
work.

## bastion as a library

It might be desirable to integrate bastion functionality in an existing binary,
for example because there is only one IP address and hence only one port 443 to
listen on.

In that case, you can use the `filippo.io/torchwood/bastion` package.

See [pkg.go.dev](https://pkg.go.dev/filippo.io/torchwood/bastion) for the
documentation and in particular the [package
example](https://pkg.go.dev/filippo.io/torchwood/bastion#example-package).
