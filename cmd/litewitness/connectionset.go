package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"slices"
	"time"

	"filippo.io/torchwood/internal/witness"
	"golang.org/x/net/http2"
)

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

func bastionConnectFunc(bastionSigner *signer, testCert bool, srv *http.Server) func(context.Context, string) {
	bastionCertX509, err := selfSignedCertificate(bastionSigner)
	if err != nil {
		fatal("generating self-signed certificate", "err", err)
	}
	bastionCert := tls.Certificate{
		Certificate: [][]byte{bastionCertX509},
		PrivateKey:  bastionSigner,
	}

	return func(ctx context.Context, addr string) {
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
			err := connectToBastion(ctx, addr, testCert, bastionCert, srv)
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
	}
}

var errBastionDisconnected = errors.New("connection to bastion interrupted")

func connectToBastion(ctx context.Context, bastion string, testCert bool, cert tls.Certificate, srv *http.Server) error {
	slog.Info("connecting to bastion", "bastion", bastion)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var roots *x509.CertPool
	if testCert {
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
