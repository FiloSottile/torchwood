package bastion_test

import (
	"crypto/sha256"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"filippo.io/torchwood/bastion"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

func Example() {
	// This example shows how to serve on the same address both a bastion
	// endpoint, and an unrelated HTTPS server.

	m := &autocert.Manager{
		Cache:      autocert.DirCache("/var/lib/example-autocert/"),
		Prompt:     autocert.AcceptTOS,
		Email:      "acme@example.com",
		HostPolicy: autocert.HostWhitelist("bastion.example.com", "www.example.com"),
	}

	var allowedBackendsMu sync.RWMutex
	var allowedBackends map[[sha256.Size]byte]bool
	b, err := bastion.New(&bastion.Config{
		AllowedBackend: func(keyHash [sha256.Size]byte) bool {
			allowedBackendsMu.RLock()
			defer allowedBackendsMu.RUnlock()
			return allowedBackends[keyHash]
		},
		GetCertificate: m.GetCertificate,
	})
	if err != nil {
		log.Fatalf("failed to load bastion: %v", err)
	}

	mux := http.NewServeMux()
	// Note the use of a host-specific pattern to route HTTP requests for the
	// bastion endpoint to the Bastion implementation.
	mux.Handle("bastion.example.com/", b)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<p>Hello, world")
	})

	hs := &http.Server{
		Addr:         "127.0.0.1:1337",
		Handler:      http.MaxBytesHandler(mux, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    m.TLSConfig(),
	}
	// ConfigureServer sets up TLSNextProto and a tls.Config.GetConfigForClient
	// for backend connections.
	if err := b.ConfigureServer(hs, false); err != nil {
		log.Fatalln("failed to configure bastion:", err)
	}
	// HTTP/2 needs to be explicitly re-enabled if desired because it's only
	// configured automatically by net/http if TLSNextProto is nil.
	if err := http2.ConfigureServer(hs, nil); err != nil {
		log.Fatalln("failed to configure HTTP/2:", err)
	}
}
