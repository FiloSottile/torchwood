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
	"time"

	"filippo.io/age"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var (
	//go:embed templates static
	embeddedFS embed.FS

	dbPath     = flag.String("db", "keyserver.sqlite3", "path to SQLite database")
	listenAddr = flag.String("listen", "localhost:13889", "address to listen on")
)

type Server struct {
	dbpool    *sqlitex.Pool
	templates *template.Template
	hmacKey   []byte
	baseURL   string
}

type KeyData struct {
	Pubkey    string `json:"pubkey"`
	UpdatedAt int64  `json:"updated_at"`
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
	if pubkey != "" {
		if _, err := age.ParseX25519Recipient(pubkey); err != nil {
			http.Error(w, "Invalid age public key format", http.StatusBadRequest)
			return
		}

		// Store in database
		if err := s.storeKey(email, pubkey); err != nil {
			http.Error(w, "Failed to store key", http.StatusInternalServerError)
			log.Printf("database error: %v", err)
			return
		}
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

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"email":  email,
		"pubkey": data.Pubkey,
	})
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

func (s *Server) storeKey(email, pubkey string) error {
	data := KeyData{
		Pubkey:    pubkey,
		UpdatedAt: time.Now().Unix(),
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
