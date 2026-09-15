package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
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
	"strings"
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

// https://www.iana.org/assignments/ssh-parameters
// https://datatracker.ietf.org/doc/html/draft-sfluhrer-ssh-mldsa-08
const algoMLDSA44 = "ssh-mldsa-44"

func onSignal(signo os.Signal, callback func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, signo)
	go func() {
		for range c {
			callback()
		}
	}()
}

type stringSliceValue []string

func (ss *stringSliceValue) String() string {
	return fmt.Sprint(*ss)
}
func (ss *stringSliceValue) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

func main() {
	var nameFlag = flag.String("name", "", "URL-like (e.g. example.com/foo) name of this witness")
	var dbFlag = flag.String("db", "litewitness.db", "path to sqlite database")
	var sshAgentFlag = flag.String("ssh-agent", "litewitness.sock", "path to ssh-agent socket")
	var listenFlag = flag.String("listen", "localhost:7380", "address to listen for HTTP requests")
	var noListenFlag = flag.Bool("no-listen", false, "do not open any listening socket, rely exclusively on bastions")
	var keyFlags stringSliceValue
	flag.Var(&keyFlags, "key", "SSH fingerprint (with SHA256: prefix) of a witness key, Ed25519 or ML-DSA-44. Can be used several times.")
	var bastionKeyFlag = flag.String("bastion-key", "", "SSH fingerprint (with SHA256: prefix) of key for authenticating with bastions")
	var testCertFlag = flag.Bool("testcert", false, "use rootCA.pem for connections to the bastion")
	var obscurityFlag = flag.Bool("obscurity", false, "enable obscurity mode (disable / and /logz endpoints)")
	var listenMetricsFlag = flag.String("listen-metrics", "", "address to listen for metrics requests, instead of exposing them on the main listener")
	flag.Parse()
	if len(flag.Args()) > 0 {
		fatal("Too many arguments", "args", flag.Args())
	}
	if len(keyFlags) == 0 {
		fatal("At least one -key is required for a witness")
	}

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

	bastionSigner, signers := connectToSSHAgent(*sshAgentFlag, *bastionKeyFlag, keyFlags)

	cryptoSigners := make([]crypto.Signer, len(signers))
	for i, s := range signers {
		cryptoSigners[i] = s
	}
	w, err := witness.NewWitness(*dbFlag, *nameFlag, cryptoSigners, slog.Default())
	if err != nil {
		fatal("creating witness", "err", err)
	}
	slog.Info("verifier keys", "vkeys", strings.Join(w.VerifierKeys(), " "))

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

	var bastionSet *ConnectionSet
	if bastionSigner != nil {
		bastionSet = NewConnectionSet(bastionConnectFunc(bastionSigner, *testCertFlag, srv))
		// Printing bastion key in hex-encoded format is useful
		slog.Info("bastion key", "pubkeyhash", fmt.Sprintf("%x", sha256.Sum256(bastionSigner.Public().(ed25519.PublicKey))))
	} else {
		bastionSet = NewConnectionSet(bastionNoKeyConnectFunc())
		slog.Info("no bastion key is configured, connections to bastions will not be possible")
	}

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

func connectToSSHAgent(sshAgent string, bastionKey string, witnessKeys []string) (*signer, []*signer) {
	conn, err := net.Dial("unix", sshAgent)
	if err != nil {
		fatal("dialing ssh-agent", "err", err)
	}
	a := agent.NewClient(conn)
	agentSigners, err := a.Signers()
	if err != nil {
		fatal("getting keys from ssh-agent", "err", err)
	}
	slog.Info("connected to ssh-agent", "addr", sshAgent)

	usableSigners := make(map[string]*signer)
	var allKeys []string
	for _, s := range agentSigners {
		allKeys = append(allKeys, (&signer{s: s}).algoFingerprint())
		switch s.PublicKey().Type() {
		case ssh.KeyAlgoED25519:
			signer, err := newED25519Signer(s)
			if err != nil {
				fatal("newED25519Signer", "err", err)
			}
			usableSigners[signer.fingerprint()] = signer
			// For backwards compatibility, keep the Ed25519s also by
			// hex-encoded SHA-256 hash of the public key, which is
			// what -key used to be.
			hh := sha256.Sum256(signer.Public().(ed25519.PublicKey))
			h := hex.EncodeToString(hh[:])
			usableSigners[h] = signer
		case algoMLDSA44:
			signer, err := newMLDSA44Signer(s)
			if err != nil {
				fatal("newMLDSA44Signer", "err", err)
			}
			usableSigners[signer.fingerprint()] = signer
		}
	}

	var bastionSigner *signer
	if bastionKey != "" {
		if signer, ok := usableSigners[bastionKey]; ok {
			bastionSigner = signer
		} else {
			fatal(fmt.Sprintf("bastion key %s not found in ssh-agent", bastionKey),
				"available", strings.Join(allKeys, " "))
		}
	}

	var witnessSigners []*signer
	for _, k := range witnessKeys {
		if signer, ok := usableSigners[k]; ok {
			witnessSigners = append(witnessSigners, signer)
		}
	}

	var fps []string
	for _, s := range witnessSigners {
		fps = append(fps, s.algoFingerprint())
	}
	slog.Info("found witness keys", "count", len(witnessSigners), "fingerprints", strings.Join(fps, " "))

	if found, wanted := len(witnessSigners), len(witnessKeys); found != wanted {
		fatal(fmt.Sprintf("found %d of %d wanted witness keys in ssh-agent", found, wanted),
			"available", strings.Join(allKeys, " "))
	}

	return bastionSigner, witnessSigners
}

type signer struct {
	s ssh.Signer
	p crypto.PublicKey
}

func newED25519Signer(s ssh.Signer) (*signer, error) {
	// agent.Key doesn't implement ssh.CryptoPublicKey.
	k, err := ssh.ParsePublicKey(s.PublicKey().Marshal())
	if err != nil {
		return nil, fmt.Errorf("internal error: ssh Ed25519 public key can't be parsed; err: %w", err)
	}
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh Ed25519 public key can't be retrieved")
	}
	pk, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key type is not Ed25519")
	}
	return &signer{s: s, p: pk}, nil
}

func newMLDSA44Signer(s ssh.Signer) (*signer, error) {
	k := struct {
		Algo string
		Pub  []byte
	}{}
	if err := ssh.Unmarshal(s.PublicKey().Marshal(), &k); err != nil {
		return nil, fmt.Errorf("internal error: ssh ML-DSA-44 public key can't be parsed; err: %w", err)
	}
	if k.Algo != algoMLDSA44 {
		return nil, fmt.Errorf("internal error: ssh public key algo is not %q", algoMLDSA44)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k.Pub)
	if err != nil {
		return nil, fmt.Errorf("internal error: ssh public key type is not MLDSA44; err: %w", err)
	}
	return &signer{s: s, p: pk}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.p
}

func (s *signer) fingerprint() string {
	return ssh.FingerprintSHA256(s.s.PublicKey())
}

func (s *signer) algoFingerprint() string {
	return fmt.Sprintf("%s|%s", s.s.PublicKey().Type(), s.fingerprint())
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
		for _, vkey := range w.VerifierKeys() {
			fmt.Fprintf(rw, "%s\n", html.EscapeString(vkey))
		}
		fmt.Fprintf(rw, "\n")
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
