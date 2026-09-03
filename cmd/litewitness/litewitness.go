package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/http2"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"filippo.io/torchwood/internal/slogconsole"
	"filippo.io/torchwood/internal/witness"
)

const algoMLDSA44Sigsum = "mldsa-44@sigsum.org"

var nameFlag = flag.String("name", "", "URL-like (e.g. example.com/foo) name of this witness")
var dbFlag = flag.String("db", "litewitness.db", "path to sqlite database")
var sshAgentFlag = flag.String("ssh-agent", "litewitness.sock", "path to ssh-agent socket")
var listenFlag = flag.String("listen", "localhost:7380", "address to listen for HTTP requests")
var noListenFlag = flag.Bool("no-listen", false, "do not open any listening socket, rely exclusively on bastions")
var keyFlag = flag.String("key", "", "SSH fingerprint of Ed25519 witness key (with SHA256: prefix), also used for authentication with bastion")
var mldsaKeyFlag = flag.String("mldsa-key", "", "SSH fingerprint of ML-DSA-44 witness key (with SHA256: prefix)")
var testCertFlag = flag.Bool("testcert", false, "use rootCA.pem for connections to the bastion")
var obscurityFlag = flag.Bool("obscurity", false, "enable obscurity mode (disable / and /logz endpoints)")
var listenMetricsFlag = flag.String("listen-metrics", "", "address to listen for metrics requests, instead of exposing them on the main listener")

type ConnectionSet struct {
	connections map[string]func() // connection => cancel func
	connect     func(context.Context, string)
}

func NewConnectionSet(connect func(context.Context, string)) *ConnectionSet {
	return &ConnectionSet{
		connections: make(map[string]func()),
		connect:     connect,
	}
}

func (s *ConnectionSet) Configure(ctx context.Context, addrs []string) {
	slices.Sort(addrs)

	// Disconnect addresses that have disappeared.
	var toDelete []string
	for addr, cancel := range s.connections {
		if _, found := slices.BinarySearch(addrs, addr); !found {
			cancel()
			// Postpone delete, we can't delete while iterating over the map.
			toDelete = append(toDelete, addr)
		}
	}
	for _, addr := range toDelete {
		delete(s.connections, addr)
	}

	// Connect new bastions.
	for _, addr := range addrs {
		if _, found := s.connections[addr]; found {
			continue
		}
		// Quit early on cancel.
		if ctx.Err() != nil {
			break
		}
		connectionCtx, cancel := context.WithCancel(ctx)
		s.connections[addr] = cancel
		go s.connect(connectionCtx, addr)
	}
}

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
	flag.Parse()
	if len(flag.Args()) > 0 {
		fatal("Too many arguments", "args", flag.Args())
	}
	if *keyFlag == "" {
		fatal("Flag -key is required")
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

	signers := connectToSSHAgent()

	var bastionSigner *signer
	for i := range signers {
		// Use the sole, required Ed25519 signer
		if *keyFlag == signers[i].sshFP() {
			bastionSigner = signers[i]
		}
	}
	bastionCertX509, err := selfSignedCertificate(bastionSigner)
	if err != nil {
		fatal("generating self-signed certificate", "err", err)
	}
	bastionCert := tls.Certificate{
		Certificate: [][]byte{bastionCertX509},
		PrivateKey:  bastionSigner,
	}

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
		mux.Handle("/{$}", indexHandler(w))
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

	bastionSet := NewConnectionSet(func(ctx context.Context, addr string) {
		var delays = []time.Duration{
			100 * time.Millisecond,
			1 * time.Second, 1 * time.Second, 1 * time.Second,
			5 * time.Second, 15 * time.Second, 30 * time.Second,
			1 * time.Minute,
		}

		// If a connection survives for resetRetryDelay, reset the retry delay.
		const resetRetryDelay = 5 * time.Minute

		retry := 0
		for {
			startTime := time.Now()
			err := connectToBastion(ctx, addr, bastionCert, srv)
			duration := time.Since(startTime)
			slog.Warn("bastion connection failed", "bastion", addr, "duration", duration, "err", err)

			// Quit early on cancel.
			if ctx.Err() != nil {
				return
			}

			// If the connection lasted long enough, reset the retry delay.
			if duration >= resetRetryDelay {
				retry = 0
			}

			// Wait before retrying.
			var delay time.Duration
			if retry < len(delays) {
				delay = delays[retry]
			} else {
				delay = delays[len(delays)-1]
			}
			slog.Info("waiting before reconnecting to bastion", "bastion", addr, "delay", delay)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			retry++
		}
	})

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

func connectToSSHAgent() []*signer {
	conn, err := net.Dial("unix", *sshAgentFlag)
	if err != nil {
		fatal("dialing ssh-agent", "err", err)
	}
	a := agent.NewClient(conn)
	aSigners, err := a.Signers()
	if err != nil {
		fatal("getting keys from ssh-agent", "err", err)
	}
	slog.Info("connected to ssh-agent", "addr", *sshAgentFlag)
	var signers []*signer
	var availableKeys []string
	for _, s := range aSigners {
		availableKeys = append(availableKeys, fmt.Sprintf("%s|%s", s.PublicKey().Type(), ssh.FingerprintSHA256(s.PublicKey())))
		switch s.PublicKey().Type() {
		case ssh.KeyAlgoED25519:
			ss, err := newED25519Signer(s)
			if err != nil {
				fatal("newED25519Signer", "err", err)
			}
			if ss.sshFP() == *keyFlag {
				signers = append(signers, ss)
			}
			// For backwards compatibility, also accept a hex-encoded SHA-256
			// hash of the public key, which is what -key used to be.
			hh := sha256.Sum256(ss.Public().(ed25519.PublicKey))
			h := hex.EncodeToString(hh[:])
			if h == *keyFlag {
				signers = append(signers, ss)
				*keyFlag = ss.sshFP()
			}
		case algoMLDSA44Sigsum:
			ss, err := newMLDSA44Signer(s)
			if err != nil {
				fatal("newMLDSA44Signer", "err", err)
			}
			if ss.sshFP() == *mldsaKeyFlag {
				signers = append(signers, ss)
			}
		}
	}

	if *keyFlag != "" && !slices.ContainsFunc(signers, func(ss *signer) bool { return ss.sshFP() == *keyFlag }) {
		fatal("ssh-agent does not contain expected key", ssh.KeyAlgoED25519, *keyFlag, "available", availableKeys)
	}
	if *mldsaKeyFlag != "" && !slices.ContainsFunc(signers, func(ss *signer) bool { return ss.sshFP() == *mldsaKeyFlag }) {
		fatal("ssh-agent does not contain expected key", algoMLDSA44Sigsum, *mldsaKeyFlag, "available", availableKeys)
	}

	fps := make([]string, len(signers))
	for i := range signers {
		fps[i] = signers[i].sshFP()
	}
	slog.Info("found keys", "fingerprints", strings.Join(fps, " "))

	return signers
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
	if k.Algo != algoMLDSA44Sigsum {
		return nil, fmt.Errorf("internal error: ssh public key algo is not %q", algoMLDSA44Sigsum)
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

func (ss *signer) sshFP() string {
	return ssh.FingerprintSHA256(ss.s.PublicKey())
}

func indexHandler(w *witness.Witness) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		db, err := witness.OpenDB(*dbFlag)
		if err != nil {
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(rw, indexHeader)
		fmt.Fprintf(rw, "# litewitness %s\n\n", html.EscapeString(*nameFlag))
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

var errBastionDisconnected = errors.New("connection to bastion interrupted")

func connectToBastion(ctx context.Context, bastion string, cert tls.Certificate, srv *http.Server) error {
	slog.Info("connecting to bastion", "bastion", bastion)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var roots *x509.CertPool
	if *testCertFlag {
		roots = x509.NewCertPool()
		root, err := os.ReadFile("rootCA.pem")
		if err != nil {
			fatal("reading test root", "err", err)
		}
		roots.AppendCertsFromPEM(root)
	}
	conn, err := (&tls.Dialer{
		Config: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"bastion/0"},
			RootCAs:      roots,
		},
	}).DialContext(dialCtx, "tcp", bastion)
	if err != nil {
		slog.Info("connecting to bastion failed", "bastion", bastion, "err", err)
		return fmt.Errorf("connecting to bastion: %v", err)
	}
	// Ensure that the connection is closed when our context is cancelled.
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	go func(ctx context.Context) {
		// TODO: gracefully complete in-flight requests.
		<-ctx.Done()
		conn.Close()
	}(ctx)

	slog.Info("connected to bastion", "bastion", bastion)
	ctx = witness.ContextWithBastion(ctx, bastion)
	// TODO: find a way to surface the fatal error, especially since with
	// TLS 1.3 it might be that the bastion rejected the client certificate.
	(&http2.Server{
		CountError: func(errType string) {
			slog.Debug("HTTP/2 server error", "type", errType)
		},
	}).ServeConn(conn, &http2.ServeConnOpts{
		Context:    ctx,
		BaseConfig: srv,
		Handler:    srv.Handler,
	})
	return errBastionDisconnected
}

func selfSignedCertificate(key crypto.Signer) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "litewitness"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
