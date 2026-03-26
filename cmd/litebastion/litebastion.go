// Command litebastion runs a reverse proxy service that allows un-addressable
// applications (for example those running behind a firewall or a NAT, or where
// the operator doesn't wish to take the DoS risk of being reachable from the
// Internet) to accept HTTP requests.
//
// Backends are identified by an Ed25519 public key, they authenticate with a
// self-signed TLS 1.3 certificate, and are reachable at a sub-path prefixed by
// the key hash.
//
// Read more at https://c2sp.org/https-bastion.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/torchwood/bastion"
	"filippo.io/torchwood/internal/slogconsole"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
)

var listenAddr = flag.String("listen", "localhost:8443", "host and port to listen at")
var listenHTTP = flag.String("listen-http", "", "host:port or localhost port to listen for HTTP requests")
var tlsCertFile = flag.String("tls-cert", "", "path to TLS certificate; disables ACME")
var tlsKeyFile = flag.String("tls-key", "", "path to TLS private key; disables ACME")
var autocertCache = flag.String("cache", "", "directory to cache ACME certificates at")
var autocertHost = flag.String("host", "", "host to obtain ACME certificate for")
var autocertEmail = flag.String("email", "", "")
var allowedBackendsFile = flag.String("backends", "", "file of accepted key hashes, one per line, reloaded on SIGHUP")
var homeRedirect = flag.String("home-redirect", "", "redirect / to this URL")
var obscurityFlag = flag.Bool("obscurity", false, "enable obscurity mode (disable /logz endpoint)")

type keyHash [sha256.Size]byte

func main() {
	flag.Parse()

	console := slogconsole.New(nil)
	console.SetFilter(slogconsole.IPAddressFilter)
	h := slog.NewTextHandler(os.Stderr, nil)
	slog.SetDefault(slog.New(slogconsole.MultiHandler(h, console)))

	http2.VerboseLogs = true // will go to DEBUG due to SetLogLoggerLevel
	slog.SetLogLoggerLevel(slog.LevelDebug)

	var reloadCert func() error
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	switch {
	case *tlsKeyFile != "" && *tlsCertFile != "":
		var cert atomic.Pointer[tls.Certificate]
		reloadCert = func() error {
			c, err := tls.LoadX509KeyPair(*tlsCertFile, *tlsKeyFile)
			if err != nil {
				return err
			}
			cert.Store(&c)
			return nil
		}
		if err := reloadCert(); err != nil {
			logFatal("can't load certificates", "err", err)
		}
		getCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert.Load(), nil
		}
	case *autocertCache != "" && *autocertHost != "" && *autocertEmail != "":
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*autocertCache),
			Prompt:     autocert.AcceptTOS,
			Email:      *autocertEmail,
			HostPolicy: autocert.HostWhitelist(*autocertHost),
		}
		getCertificate = m.GetCertificate
		reloadCert = func() error { return nil }
	default:
		logFatal("-cache, -host, and -email or -tls-key and -tls-cert are required")
	}

	if *allowedBackendsFile == "" {
		logFatal("-backends is missing")
	}
	var allowedBackendsMu sync.RWMutex
	var allowedBackends map[keyHash]bool
	reloadBackends := func() error {
		newBackends := make(map[keyHash]bool)
		backendsList, err := os.ReadFile(*allowedBackendsFile)
		if err != nil {
			return err
		}
		bs := strings.TrimSpace(string(backendsList))
		for _, line := range strings.Split(bs, "\n") {
			if line == "" {
				continue
			}
			l, err := hex.DecodeString(line)
			if err != nil {
				return fmt.Errorf("invalid backend: %q", line)
			}
			if len(l) != sha256.Size {
				return fmt.Errorf("invalid backend: %q", line)
			}
			h := keyHash(l)
			newBackends[h] = true
		}
		allowedBackendsMu.Lock()
		defer allowedBackendsMu.Unlock()
		allowedBackends = newBackends
		return nil
	}
	if err := reloadBackends(); err != nil {
		logFatal("failed to load backends", "err", err)
	}
	slog.Info("loaded backends", "count", len(allowedBackends))

	b, err := bastion.New(&bastion.Config{
		AllowedBackend: func(keyHash [sha256.Size]byte) bool {
			allowedBackendsMu.RLock()
			defer allowedBackendsMu.RUnlock()
			return allowedBackends[keyHash]
		},
		GetCertificate: getCertificate,
	})
	if err != nil {
		logFatal("failed to create bastion", "err", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			if err := reloadCert(); err != nil {
				slog.Error("failed to reload certificate", "err", err)
			}
			if err := reloadBackends(); err != nil {
				slog.Error("failed to reload backends", "err", err)
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				b.FlushBackendConnections(ctx)
				cancel()
				slog.Info("reloaded backends")
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/", b)
	if !*obscurityFlag {
		mux.Handle("/logz", console)
	}
	if *homeRedirect != "" {
		mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, *homeRedirect, http.StatusFound)
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	serveGroup, ctx := errgroup.WithContext(ctx)

	if *listenHTTP != "" {
		if _, _, err := net.SplitHostPort(*listenHTTP); err != nil {
			*listenHTTP = net.JoinHostPort("localhost", *listenHTTP)
		}
		hs := &http.Server{
			Addr:         *listenHTTP,
			Handler:      http.MaxBytesHandler(mux, 10*1024),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		l, err := net.Listen("tcp", *listenAddr)
		if err != nil {
			logFatal("failed to listen for backends", "err", err)
		}
		serveGroup.Go(func() error {
			slog.Info("listening for HTTP", "addr", hs.Addr)
			return hs.ListenAndServe()
		})
		serveGroup.Go(func() error {
			slog.Info("listening for backends", "addr", *listenAddr)
			for {
				c, err := l.Accept()
				if err != nil {
					return err
				}
				go b.HandleBackendConnection(c)
			}
		})
		serveGroup.Go(func() error {
			<-ctx.Done()
			slog.Info("shutting down bastion listener")
			l.Close()
			slog.Info("shutting down HTTP server")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			hs.Shutdown(ctx)
			return nil
		})
		serveGroup.Wait()
		slog.Info("exiting", "err", context.Cause(ctx))
		return
	}

	hs := &http.Server{
		Addr:         *listenAddr,
		Handler:      http.MaxBytesHandler(mux, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:     []string{acme.ALPNProto},
			GetCertificate: getCertificate,
		},
	}
	if err := b.ConfigureServer(hs); err != nil {
		logFatal("failed to configure bastion", "err", err)
	}
	if err := http2.ConfigureServer(hs, nil); err != nil {
		logFatal("failed to configure HTTP/2", "err", err)
	}

	slog.Info("listening", "addr", *listenAddr)
	e := make(chan error, 1)
	go func() { e <- hs.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		slog.Info("shutting down on interrupt")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	case err := <-e:
		slog.Error("server error", "err", err)
	}
}

func logFatal(msg string, args ...interface{}) {
	slog.Error(msg, args...)
	os.Exit(1)
}
