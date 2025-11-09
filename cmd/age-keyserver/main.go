package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/torchwood"
	"filippo.io/torchwood/tesserax"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var (
	//go:embed templates static
	embeddedFS embed.FS

	dbPath     = flag.String("db", "keyserver.sqlite3", "path to SQLite database")
	logPath    = flag.String("logdir", "keyserver-tlog", "directory for transparency log")
	listenAddr = flag.String("listen", "localhost:13889", "address to listen on")
)

type Server struct {
	dbpool    *sqlitex.Pool
	templates *template.Template
	hmacKey   []byte
	baseURL   string
	reader    tessera.LogReader
	appender  *tessera.Appender
	awaiter   *tessera.PublicationAwaiter
	policy    torchwood.Policy
}

type KeyData struct {
	Pubkey    string `json:"pubkey"`
	UpdatedAt int64  `json:"updated_at"`
	LogIndex  int64  `json:"log_index"`
}

const (
	linkValidDuration = 10 * time.Minute
	schema            = `
		CREATE TABLE IF NOT EXISTS keys (
			email TEXT PRIMARY KEY,
			json_data BLOB
		) STRICT;`
)

func main() {
	flag.Parse()
	ctx := context.Background()

	s, err := note.NewSigner(os.Getenv("LOG_KEY"))
	if err != nil {
		log.Fatalln("failed to create checkpoint signer:", err)
	}
	v, err := torchwood.NewVerifierFromSigner(os.Getenv("LOG_KEY"))
	if err != nil {
		log.Fatalln("failed to create checkpoint verifier:", err)
	}
	policy := torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(v.Name()),
		torchwood.SingleVerifierPolicy(v))

	driver, err := posix.New(ctx, posix.Config{
		Path: *logPath,
	})
	if err != nil {
		log.Fatalln("failed to create log storage driver:", err)
	}

	// Since this is a low-traffic but interactive server, disable batching to
	// remove integration latency for the first request. Keep a 1s checkpoint
	// interval not to hit the witnesses too often; this will be observed only
	// if two requests come in quick succession. Finally, only publish a
	// checkpoint once a day if there are no new entries, making the average qps
	// on witnesses low. Poll for new checkpoints quickly since it should be
	// just a read from a hot filesystem cache.
	checkpointInterval := 1 * time.Second
	if testing.Testing() {
		checkpointInterval = 100 * time.Millisecond
	}
	appender, shutdown, logReader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(s).
		WithBatching(1, tessera.DefaultBatchMaxAge).
		WithCheckpointInterval(checkpointInterval).
		WithCheckpointRepublishInterval(24*time.Hour))
	if err != nil {
		log.Fatalln("failed to create log appender:", err)
	}
	defer shutdown(context.Background())
	awaiter := tessera.NewPublicationAwaiter(ctx, logReader.ReadCheckpoint, 25*time.Millisecond)

	// Check for development vs production mode
	postmarkToken := os.Getenv("POSTMARK_TOKEN")
	if postmarkToken == "" {
		log.Println("Running in DEVELOPMENT mode (POSTMARK_TOKEN not set)")
		log.Println("Login links will be logged to console instead of emailed")
	}

	// Generate random HMAC key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		log.Fatalln("failed to generate HMAC key:", err)
	}
	log.Printf("Generated HMAC key (will invalidate on restart)")

	// Initialize database
	dbpool, err := sqlitex.NewPool(*dbPath, sqlitex.PoolOptions{
		PoolSize: 10,
		PrepareConn: func(conn *sqlite.Conn) error {
			return sqlitex.ExecuteTransient(conn, schema, nil)
		},
	})
	if err != nil {
		log.Fatalln("failed to open database:", err)
	}
	defer dbpool.Close()

	// Parse templates
	tmplFS, err := fs.Sub(embeddedFS, "templates")
	if err != nil {
		log.Fatalln("failed to get templates subdirectory:", err)
	}
	templates := template.Must(template.ParseFS(tmplFS, "*.html"))

	// Determine base URL
	var baseURL string
	if postmarkToken == "" {
		// Development mode: use listen address
		baseURL = fmt.Sprintf("http://%s", *listenAddr)
	} else {
		// Production mode: use hardcoded production URL
		baseURL = "https://keyserver.geomys.org"
	}

	// Create server
	srv := &Server{
		dbpool:    dbpool,
		templates: templates,
		hmacKey:   hmacKey,
		baseURL:   baseURL,
		reader:    logReader,
		appender:  appender,
		awaiter:   awaiter,
		policy:    policy,
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", srv.handleHome)
	mux.HandleFunc("POST /login", srv.handleLogin)
	mux.HandleFunc("GET /manage", srv.handleManage)
	mux.HandleFunc("POST /setkey", srv.handleSetKey)
	mux.HandleFunc("GET /api/lookup", srv.handleLookup)
	mux.HandleFunc("POST /api/verify-token", srv.handleVerifyToken)

	// Serve static files
	staticFS, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		log.Fatalln("failed to get static subdirectory:", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Serve tlog-tiles log
	fs := http.StripPrefix("/tlog/", http.FileServer(http.Dir(*logPath)))
	mux.Handle("GET /tlog/", fs)

	// Start server with h2c support
	log.Println("")
	log.Printf("Starting age Keyserver on %s", *listenAddr)
	log.Printf("Open in browser: http://%s", *listenAddr)
	log.Println("")
	h2s := &http2.Server{}
	handler := h2c.NewHandler(mux, h2s)
	handler = http.MaxBytesHandler(handler, 1<<16) // 64KB max request size

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: handler,
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalln("server error:", err)
	}
	log.Println("shutting down")
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	hcaptchaSitekey := os.Getenv("HCAPTCHA_SITEKEY")
	if hcaptchaSitekey == "" {
		hcaptchaSitekey = "10000000-ffff-ffff-ffff-000000000001" // hCaptcha test key
	}
	data := map[string]string{
		"HCaptchaSitekey": hcaptchaSitekey,
	}
	if err := s.templates.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	captchaResponse := r.FormValue("h-captcha-response")

	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}
	// Emails are technically case sensitive, but users are unlikely to monitor
	// all case variations, so we normalize to lowercase. We do it before
	// sending the login link, so normalization can't lead to impersonation.
	email = strings.ToLower(email)
	if strings.ContainsAny(email, "\n") {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Verify captcha
	if !verifyCaptcha(captchaResponse) {
		http.Error(w, "Captcha verification failed", http.StatusBadRequest)
		return
	}

	// Generate login link
	loginLink, ts, sig := s.generateLoginLink(email, r)

	// Send email via Postmark
	if err := sendLoginEmail(email, loginLink, ts, sig); err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		log.Printf("email error: %v", err)
		return
	}

	// Show confirmation page
	if err := s.templates.ExecuteTemplate(w, "login_sent.html", map[string]string{
		"Email": email,
	}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleManage(w http.ResponseWriter, r *http.Request) {
	// Now the token is in the URL fragment, handled client-side
	// Just serve the manage.html page which will process the fragment
	if err := s.templates.ExecuteTemplate(w, "manage.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Ts    string `json:"ts"`
		Sig   string `json:"sig"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify signature and timestamp
	if !s.verifyLoginLink(req.Email, req.Sig, req.Ts) {
		http.Error(w, "Invalid or expired login link", http.StatusUnauthorized)
		return
	}

	// Get current key data if exists
	keyData, err := s.getKeyData(req.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("database error: %v", err)
		return
	}

	// Return verification response
	w.Header().Set("Content-Type", "application/json")
	if keyData != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"currentKey": keyData.Pubkey,
			"updatedAt":  keyData.UpdatedAt,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]any{
			"currentKey": "",
		})
	}
}

func (s *Server) handleSetKey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	sig := r.FormValue("sig")
	ts := r.FormValue("ts")
	pubkey := strings.TrimSpace(r.FormValue("pubkey"))

	// Verify auth
	if !s.verifyLoginLink(email, sig, ts) {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Validate age public key
	var proof string
	if pubkey != "" {
		if _, err := age.ParseX25519Recipient(pubkey); err != nil {
			http.Error(w, "Invalid age public key format", http.StatusBadRequest)
			return
		}

		// Add to transparency log
		entry := tessera.NewEntry(fmt.Appendf(nil, "%s\n%s\n", email, pubkey))
		index, _, err := s.awaiter.Await(r.Context(), s.appender.Add(r.Context(), entry))
		if err != nil {
			http.Error(w, "Failed to add to transparency log", http.StatusInternalServerError)
			log.Printf("transparency log error: %v", err)
			return
		}

		// Store in database
		if err := s.storeKey(email, pubkey, int64(index.Index)); err != nil {
			http.Error(w, "Failed to store key", http.StatusInternalServerError)
			log.Printf("database error: %v", err)
			return
		}

		// Generate proof for success page
		proofBytes, err := s.makeSpicySignature(r.Context(), int64(index.Index))
		if err != nil {
			http.Error(w, "Failed to create proof", http.StatusInternalServerError)
			log.Printf("proof error: %v", err)
			return
		}
		proof = string(proofBytes)
	} else {
		// Delete key
		if err := s.deleteKey(email); err != nil {
			http.Error(w, "Failed to delete key", http.StatusInternalServerError)
			log.Printf("database error: %v", err)
			return
		}
	}

	// Show success page
	if err := s.templates.ExecuteTemplate(w, "success.html", map[string]string{
		"Email":  email,
		"Pubkey": pubkey,
		"Proof":  proof,
	}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email parameter required", http.StatusBadRequest)
		return
	}

	data, err := s.getKeyData(email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("database error: %v", err)
		return
	}
	if data == nil {
		http.Error(w, "No key found for this email", http.StatusNotFound)
		return
	}

	proof, err := s.makeSpicySignature(r.Context(), data.LogIndex)
	if err != nil {
		http.Error(w, "Failed to create proof", http.StatusInternalServerError)
		log.Printf("proof error: %v", err)
		return
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"email":  email,
		"pubkey": data.Pubkey,
		"proof":  string(proof),
	})
}

func (s *Server) makeSpicySignature(ctx context.Context, index int64) ([]byte, error) {
	checkpoint, err := s.reader.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint: %v", err)
	}
	c, _, err := torchwood.VerifyCheckpoint(checkpoint, s.policy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %v", err)
	}
	p, err := tlog.ProveRecord(c.N, index, torchwood.TileHashReaderWithContext(
		ctx, c.Tree, tesserax.NewTileReader(s.reader)))
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %v", err)
	}
	return torchwood.FormatProof(index, p, checkpoint), nil
}

func (s *Server) generateHMAC(email string, ts int64) string {
	msg := fmt.Sprintf("%s:%d", email, ts)
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(msg))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Server) generateLoginLink(email string, r *http.Request) (loginLink string, ts int64, sig string) {
	ts = time.Now().Unix()
	sig = s.generateHMAC(email, ts)
	loginLink = fmt.Sprintf("%s/manage#email=%s&ts=%d&sig=%s",
		s.baseURL,
		url.QueryEscape(email),
		ts,
		url.QueryEscape(sig))
	return
}

func (s *Server) verifyLoginLink(email, sig, tsStr string) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	// Check if expired
	if time.Since(time.Unix(ts, 0)) > linkValidDuration {
		return false
	}

	// Verify HMAC
	msg := fmt.Sprintf("%s:%d", email, ts)
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(msg))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

func (s *Server) getKeyData(email string) (*KeyData, error) {
	conn, err := s.dbpool.Take(context.Background())
	if err != nil {
		return nil, err
	}
	defer s.dbpool.Put(conn)

	var jsonData []byte
	err = sqlitex.Execute(conn, "SELECT json(json_data) FROM keys WHERE email = ?", &sqlitex.ExecOptions{
		Args: []any{email},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			jsonData = make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, jsonData)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	if len(jsonData) == 0 {
		return nil, nil
	}

	var data KeyData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *Server) storeKey(email, pubkey string, index int64) error {
	data := KeyData{
		Pubkey:    pubkey,
		UpdatedAt: time.Now().Unix(),
		LogIndex:  index,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	conn, err := s.dbpool.Take(context.Background())
	if err != nil {
		return err
	}
	defer s.dbpool.Put(conn)

	return sqlitex.Execute(conn, `
		INSERT INTO keys (email, json_data)
		VALUES (?, JSONB(?))
		ON CONFLICT(email) DO UPDATE SET
			json_data = excluded.json_data
	`, &sqlitex.ExecOptions{
		Args: []any{email, string(jsonData)},
	})
}

func (s *Server) deleteKey(email string) error {
	conn, err := s.dbpool.Take(context.Background())
	if err != nil {
		return err
	}
	defer s.dbpool.Put(conn)

	return sqlitex.Execute(conn, "DELETE FROM keys WHERE email = ?", &sqlitex.ExecOptions{
		Args: []any{email},
	})
}

func verifyCaptcha(response string) bool {
	if response == "" {
		return false
	}

	hcaptchaSecret := os.Getenv("HCAPTCHA_SECRET")
	if hcaptchaSecret == "" {
		log.Println("HCAPTCHA_SECRET not set, skipping captcha verification")
		return true // Allow in development
	}

	data := url.Values{}
	data.Set("secret", hcaptchaSecret)
	data.Set("response", response)

	resp, err := http.PostForm("https://hcaptcha.com/siteverify", data)
	if err != nil {
		log.Printf("captcha verification error: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("captcha response decode error: %v", err)
		return false
	}

	return result.Success
}

func sendLoginEmail(email, loginLink string, ts int64, sig string) error {
	postmarkToken := os.Getenv("POSTMARK_TOKEN")
	if postmarkToken == "" {
		// Development mode: log the link instead of emailing
		log.Printf("%s", loginLink)

		// Write HMAC data to file if specified (for testing)
		if hmacFile := os.Getenv("AGE_KEYSERVER_HMAC_FILE"); hmacFile != "" {
			data := fmt.Sprintf("%s\n%d\n%s\n", email, ts, sig)
			if err := os.WriteFile(hmacFile, []byte(data), 0600); err != nil {
				log.Printf("warning: failed to write HMAC file: %v", err)
			}
		}
		return nil
	}

	fromEmail := os.Getenv("EMAIL_FROM")
	if fromEmail == "" {
		fromEmail = "noreply@keyserver.geomys.org"
	}

	emailBody := map[string]interface{}{
		"From":     fromEmail,
		"To":       email,
		"Subject":  "Login to age Keyserver",
		"TextBody": fmt.Sprintf("Click this link to login and manage your age public key:\n\n%s\n\nThis link will expire in 10 minutes.", loginLink),
		"HtmlBody": fmt.Sprintf(`<p>Click this link to login and manage your age public key:</p><p><a href="%s">%s</a></p><p>This link will expire in 10 minutes.</p>`, loginLink, loginLink),
	}

	body, err := json.Marshal(emailBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.postmarkapp.com/email", strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", postmarkToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("postmark API error: %s - %s", resp.Status, string(body))
	}

	return nil
}
