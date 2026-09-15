package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"filippo.io/torchwood/internal/slogconsole"
	"filippo.io/torchwood/internal/witness"
)

func onSignal(signo os.Signal, callback func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, signo)
	go func() {
		for range c {
			callback()
		}
	}()
}

func main() {
	var nameFlag = flag.String("name", "", "URL-like (e.g. example.com/foo) name of this witness")
	var dbFlag = flag.String("db", "litewitness.db", "path to sqlite database")
	var sshAgentFlag = flag.String("ssh-agent", "litewitness.sock", "path to ssh-agent socket")
	var listenFlag = flag.String("listen", "localhost:7380", "address to listen for HTTP requests")
	var noListenFlag = flag.Bool("no-listen", false, "do not open any listening socket, rely exclusively on bastions")
	var keyFlag = flag.String("key", "", "SSH fingerprint (with SHA256: prefix) of the witness key")
	var testCertFlag = flag.Bool("testcert", false, "use rootCA.pem for connections to the bastion")
	var obscurityFlag = flag.Bool("obscurity", false, "enable obscurity mode (disable / and /logz endpoints)")
	var listenMetricsFlag = flag.String("listen-metrics", "", "address to listen for metrics requests, instead of exposing them on the main listener")
	flag.Parse()

	var level = new(slog.LevelVar)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	console := slogconsole.New(nil)
	console.SetFilter(slogconsole.IPAddressFilter)
	slog.SetDefault(slog.New(slogconsole.MultiHandler(h, console)))

	onSignal(syscall.SIGUSR1, func() {
		slog.Info("received USR1 signal, toggling log level")
		if level.Level() == slog.LevelDebug {
			level.Set(slog.LevelInfo)
		} else {
			level.Set(slog.LevelDebug)
		}
	})

	signer := connectToSSHAgent(*sshAgentFlag, *keyFlag)

	w, err := witness.NewWitness(*dbFlag, *nameFlag, signer, slog.Default())
	if err != nil {
		fatal("creating witness", "err", err)
	}
	slog.Info("verifier key", "vkey", w.VerifierKey())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	metricsRegistry := prometheus.NewRegistry()
	metricsRegistry.MustRegister(collectors.NewGoCollector())
	metricsRegistry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	litewitnessMetrics := prometheus.WrapRegistererWithPrefix("litewitness_", metricsRegistry)
	witnessMetrics := prometheus.WrapRegistererWithPrefix("witness_", litewitnessMetrics)
	witnessMetrics.MustRegister(w.Metrics()...)

	metricsHandler := promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(slog.Default().Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	})

	var metricsSrv *http.Server
	if *listenMetricsFlag != "" {
		metricsSrv = &http.Server{
			Addr:         *listenMetricsFlag,
			Handler:      http.MaxBytesHandler(metricsHandler, 10*1024),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			BaseContext:  func(net.Listener) context.Context { return ctx },
		}
		go func() {
			slog.Info("listening for metrics", "addr", *listenMetricsFlag)
			err := metricsSrv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server error", "err", err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.Handle("/", w)
	if !*obscurityFlag {
		mux.Handle("/logz", console)
		mux.Handle("/{$}", indexHandler(w, *dbFlag, *nameFlag))
		if *listenMetricsFlag == "" {
			mux.Handle("/metrics", metricsHandler)
		}
	}

	srv := &http.Server{
		Addr:         *listenFlag,
		Handler:      http.MaxBytesHandler(mux, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}
	e := make(chan error, 1)

	bastionSet := NewConnectionSet(bastionConnectFunc(signer, *testCertFlag, srv))

	// Handle log-specific bastions.
	logBastions, err := w.AllBastions()
	if err != nil {
		fatal("failed looking up bastions", "err", err)
	}
	bastionSet.Configure(ctx, logBastions)

	// At this point, ownership of bastionSet belongs with the signal goroutine,
	// and must no longer be accessed by main goroutine.
	onSignal(syscall.SIGHUP, func() {
		slog.Info("received SIGHUP, reconfiguring bastions")
		logBastions, err := w.AllBastions()
		if err != nil {
			slog.Warn("failed looking up bastions", "err", err)
			return
		}
		bastionSet.Configure(ctx, logBastions)
	})

	if !*noListenFlag {
		go func() {
			slog.Info("listening", "addr", *listenFlag)
			e <- srv.ListenAndServe()
		}()
	} else if len(logBastions) == 0 {
		slog.Warn("configured to not open a listening port, but no bastions configured")
	}

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		if metricsSrv != nil {
			metricsSrv.Shutdown(ctx)
		}
	case err := <-e:
		fatal("server error", "err", err)
	}
}

func connectToSSHAgent(sshAgent string, key string) *signer {
	conn, err := net.Dial("unix", sshAgent)
	if err != nil {
		fatal("dialing ssh-agent", "err", err)
	}
	a := agent.NewClient(conn)
	signers, err := a.Signers()
	if err != nil {
		fatal("getting keys from ssh-agent", "err", err)
	}
	slog.Info("connected to ssh-agent", "addr", sshAgent)
	var signer *signer
	var keys []string
	for _, s := range signers {
		if s.PublicKey().Type() != ssh.KeyAlgoED25519 {
			continue
		}
		ss, err := newSigner(s)
		if err != nil {
			fatal("new signer", "err", err)
		}
		if ssh.FingerprintSHA256(s.PublicKey()) == key {
			signer = ss
			break
		}
		// For backwards compatibility, also accept a hex-encoded SHA-256 hash
		// of the public key, which is what -key used to be.
		hh := sha256.Sum256(ss.Public().(ed25519.PublicKey))
		h := hex.EncodeToString(hh[:])
		if h == key {
			signer = ss
			break
		}
		keys = append(keys, h)
	}
	if signer == nil {
		fatal("ssh-agent does not contain Ed25519 key", "expected", key, "found", keys)
	}
	slog.Info("found key", "fingerprint", key)
	return signer
}

type signer struct {
	s ssh.Signer
	p ed25519.PublicKey
}

func newSigner(s ssh.Signer) (*signer, error) {
	// agent.Key doesn't implement ssh.CryptoPublicKey.
	k, err := ssh.ParsePublicKey(s.PublicKey().Marshal())
	if err != nil {
		return nil, errors.New("internal error: ssh public key can't be parsed")
	}
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key can't be retrieved")
	}
	pk, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key type is not Ed25519")
	}
	return &signer{s: s, p: pk}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.p
}

func (s *signer) Sign(rand io.Reader, data []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("expected crypto.Hash(0)")
	}
	sig, err := s.s.Sign(rand, data)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

const indexHeader = `
<!DOCTYPE html>
<title>litewitness</title>
<style>
pre {
	font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro',
		Menlo, Consolas, 'DejaVu Sans Mono', monospace;
}
:root {
	color-scheme: light dark;
}
.container {
	max-width: 800px;
	margin: 100px auto;
}
</style>
<div class="container">
<pre>
`

func indexHandler(w *witness.Witness, dbPath string, name string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		db, err := witness.OpenDB(dbPath)
		if err != nil {
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(rw, indexHeader)
		fmt.Fprintf(rw, "# litewitness %s\n\n", html.EscapeString(name))
		fmt.Fprintf(rw, "%s\n\n", html.EscapeString(w.VerifierKey()))
		fmt.Fprintf(rw, "## Logs\n\n")
		sqlitex.Execute(db, "SELECT origin, tree_size, tree_hash FROM log", &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				fmt.Fprintf(rw, "- %s\n  (size %d, root %s)\n\n",
					html.EscapeString(stmt.ColumnText(0)),
					stmt.ColumnInt64(1), stmt.ColumnText(2))
				return nil
			},
		})
	}
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
