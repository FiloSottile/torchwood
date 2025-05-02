// Package bastion runs a reverse proxy service that allows un-addressable
// applications (for example those running behind a firewall or a NAT, or where
// the operator doesn't wish to take the DoS risk of being reachable from the
// Internet) to accept HTTP requests.
//
// Backends are identified by an Ed25519 public key, they authenticate with a
// self-signed TLS 1.3 certificate, and are reachable at a sub-path prefixed by
// the key hash.
//
// Read more at
// https://git.glasklar.is/sigsum/project/documentation/-/blob/main/bastion.md.
package bastion

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Config provides parameters for a new Bastion.
type Config struct {
	// GetCertificate returns the certificate for bastion backend connections.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// AllowedBackend returns whether the backend is allowed to
	// serve requests. It's passed the hash of its Ed25519 public key.
	//
	// AllowedBackend may be called concurrently.
	AllowedBackend func(keyHash [sha256.Size]byte) bool

	// Log is used to log backend connections states (as INFO) and errors in
	// forwarding requests (as DEBUG). If nil, [slog.Default] is used.
	Log *slog.Logger
}

// A Bastion keeps track of backend connections, and serves HTTP requests by
// routing them to the matching backend.
type Bastion struct {
	c     *Config
	proxy *httputil.ReverseProxy
	pool  *backendConnectionsPool
}

type keyHash [sha256.Size]byte

func (kh keyHash) String() string {
	return hex.EncodeToString(kh[:])
}

// New returns a new Bastion.
//
// The Config must not be modified after the call to New.
func New(c *Config) (*Bastion, error) {
	b := &Bastion{c: c}
	b.pool = &backendConnectionsPool{
		log:   slog.Default(),
		conns: make(map[keyHash]*http2.ClientConn),
	}
	if c.Log != nil {
		b.pool.log = c.Log
	}
	b.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https" // needed for the required :scheme header
			pr.Out.Host = pr.In.Context().Value("backend").(string)
			pr.SetXForwarded()
			// We don't interpret the query, so pass it on unmodified.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
		},
		Transport: b.pool,
		ErrorLog:  slog.NewLogLogger(b.pool.log.Handler(), slog.LevelDebug),
	}
	return b, nil
}

// ConfigureServer sets up srv to handle backend connections to the bastion. It
// wraps TLSConfig.GetConfigForClient to intercept backend connections, and sets
// TLSNextProto for the bastion ALPN protocol. The original tls.Config is still
// used for non-bastion backend connections.
//
// Note that since TLSNextProto won't be nil after a call to ConfigureServer,
// the caller might want to call [http2.ConfigureServer] as well.
func (b *Bastion) ConfigureServer(srv *http.Server) error {
	if srv.TLSNextProto == nil {
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	srv.TLSNextProto["bastion/0"] = b.pool.handleBackend

	bastionTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"bastion/0"},
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			h, err := backendHash(cs)
			if err != nil {
				return err
			}
			if !b.c.AllowedBackend(h) {
				return fmt.Errorf("unrecognized backend %x", h)
			}
			return nil
		},
		GetCertificate: b.c.GetCertificate,
	}

	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	oldGetConfigForClient := srv.TLSConfig.GetConfigForClient
	srv.TLSConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, proto := range chi.SupportedProtos {
			if proto == "bastion/0" {
				// This is a bastion connection from a backend.
				return bastionTLSConfig, nil
			}
		}
		if oldGetConfigForClient != nil {
			return oldGetConfigForClient(chi)
		}
		return nil, nil
	}

	return nil
}

func backendHash(cs tls.ConnectionState) (keyHash, error) {
	pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return keyHash{}, errors.New("self-signed certificate key type is not Ed25519")
	}
	return sha256.Sum256(pk), nil
}

// ServeHTTP serves requests rooted at "/<hex key hash>/" by routing them to the
// backend that authenticated with that key. Other requests are served a 404 Not
// Found status.
func (b *Bastion) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		http.Error(w, "request must start with /KEY_HASH/", http.StatusNotFound)
		return
	}
	path = path[1:]
	kh, path, ok := strings.Cut(path, "/")
	if !ok {
		http.Error(w, "request must start with /KEY_HASH/", http.StatusNotFound)
		return
	}
	ctx := context.WithValue(r.Context(), "backend", kh)
	r = r.Clone(ctx)
	r.URL.Path = "/" + path
	b.proxy.ServeHTTP(w, r)
}

// FlushBackendConnections closes all for backends that don't pass
// [Config.AllowedBackend] anymore.
//
// ctx is passed to [http2.ClientConn.Shutdown], and FlushBackendConnections
// waits for all connections to be closed.
func (b *Bastion) FlushBackendConnections(ctx context.Context) {
	wg := sync.WaitGroup{}
	defer wg.Wait()
	b.pool.Lock()
	defer b.pool.Unlock()
	for kh, cc := range b.pool.conns {
		if !b.c.AllowedBackend(kh) {
			wg.Add(1)
			go func() {
				if err := cc.Shutdown(ctx); err != nil {
					cc.Close()
				}
				wg.Done()
			}()
			delete(b.pool.conns, kh)
		}
	}
}

type backendConnectionsPool struct {
	log *slog.Logger
	sync.RWMutex
	conns map[keyHash]*http2.ClientConn
}

func (p *backendConnectionsPool) RoundTrip(r *http.Request) (*http.Response, error) {
	kh, err := hex.DecodeString(r.Host)
	if err != nil || len(kh) != sha256.Size {
		// TODO: return this as a response instead.
		return nil, errors.New("invalid backend key hash")
	}
	p.RLock()
	cc, ok := p.conns[keyHash(kh)]
	p.RUnlock()
	if !ok {
		// TODO: return this as a response instead.
		return nil, errors.New("backend unavailable")
	}
	rsp, err := cc.RoundTrip(r)
	if err != nil {
		// Disconnect and forget this backend.
		p.Lock()
		if p.conns[keyHash(kh)] == cc {
			delete(p.conns, keyHash(kh))
		}
		p.Unlock()
		if !cc.State().Closed {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				cc.Shutdown(ctx)
			}()
		}
	}
	return rsp, err
}

func (p *backendConnectionsPool) handleBackend(hs *http.Server, c *tls.Conn, h http.Handler) {
	backend, err := backendHash(c.ConnectionState())
	if err != nil {
		p.log.Info("failed to get backend hash", "err", err)
		return
	}
	l := p.log.With("backend", backend, "remote", c.RemoteAddr())
	t := &http2.Transport{
		// Send a PING every 15s, with the default 15s timeout.
		ReadIdleTimeout: 15 * time.Second,
		CountError: func(errType string) {
			l.Info("HTTP/2 transport error", "type", errType)
		},
	}
	cc, err := t.NewClientConn(c)
	if err != nil {
		l.Info("failed to convert to HTTP/2 client connection", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cc.Ping(ctx); err != nil {
		l.Info("did not respond to PING", "err", err)
		return
	}

	p.Lock()
	if oldCC, ok := p.conns[backend]; ok && !oldCC.State().Closed {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := oldCC.Shutdown(ctx); err != nil {
				oldCC.Close()
			}
		}()
	}
	p.conns[backend] = cc
	p.Unlock()

	l.Info("accepted new backend connection")
	// We need not to return, or http.Server will close this connection.
	// There is no way to wait for the ClientConn's closing, so we poll.
	for !cc.State().Closed {
		time.Sleep(1 * time.Second)
	}
	l.Info("backend connection closed")
}
