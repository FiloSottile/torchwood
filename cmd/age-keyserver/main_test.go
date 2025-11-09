package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age-keyserver": func() {
			main()
		},
	})
}

func TestScript(t *testing.T) {
	p := testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			bindir := filepath.SplitList(os.Getenv("PATH"))[0]
			// Build age-keylookup into the test binary directory
			cmd := exec.Command("go", "build", "-o", bindir)
			if testing.CoverMode() != "" {
				cmd.Args = append(cmd.Args, "-cover")
			}
			cmd.Args = append(cmd.Args, "filippo.io/torchwood/cmd/age-keylookup")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"waitfor": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: waitfor <file | host:port | URL>")
				}
				if strings.HasPrefix(args[0], "http") {
					var lastErr error
					for i := 0; i < 50; i++ {
						r, err := http.Get(args[0])
						if err == nil && r.StatusCode != http.StatusBadGateway {
							return
						}
						time.Sleep(100 * time.Millisecond)
						lastErr = err
					}
					ts.Fatalf("timeout waiting for %s: %v", args[0], lastErr)
				}
				protocol := "unix"
				if strings.Contains(args[0], ":") {
					protocol = "tcp"
				}
				var lastErr error
				for i := 0; i < 50; i++ {
					conn, err := net.Dial(protocol, args[0])
					if err == nil {
						conn.Close()
						return
					}
					time.Sleep(100 * time.Millisecond)
					lastErr = err
				}
				ts.Fatalf("timeout waiting for %s: %v", args[0], lastErr)
			},
			"killall": func(ts *testscript.TestScript, neg bool, args []string) {
				for _, cmd := range ts.BackgroundCmds() {
					cmd.Process.Signal(os.Interrupt)
				}
			},
			"linecount": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: linecount <file> N")
				}
				count, err := strconv.Atoi(args[1])
				if err != nil {
					ts.Fatalf("invalid count: %v", args[1])
				}
				if got := strings.Count(ts.ReadFile(args[0]), "\n"); got != count {
					ts.Fatalf("%v has %d lines, not %d", args[0], got, count)
				}
			},
			"insertkey": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 3 {
					ts.Fatalf("usage: insertkey <server-url> <email> <pubkey>")
				}
				serverURL := args[0]
				email := args[1]
				pubkey := args[2]

				// Validate the public key
				if _, err := age.ParseX25519Recipient(pubkey); err != nil {
					ts.Fatalf("invalid age public key: %v", err)
				}

				// HMAC file path (must be set in testscript env before starting server)
				hmacFile := filepath.Join(ts.Getenv("WORK"), "hmac.txt")

				// Call login endpoint to generate HMAC token
				loginForm := fmt.Sprintf("email=%s&h-captcha-response=10000000-aaaa-bbbb-cccc-000000000001",
					url.QueryEscape(email))
				resp, err := http.Post(serverURL+"/login", "application/x-www-form-urlencoded", strings.NewReader(loginForm))
				if err != nil {
					ts.Fatalf("failed to call login: %v", err)
				}
				resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					ts.Fatalf("login failed: %s", resp.Status)
				}

				// Read HMAC data from file
				hmacData, err := os.ReadFile(hmacFile)
				if err != nil {
					ts.Fatalf("failed to read HMAC file: %v", err)
				}

				lines := strings.Split(strings.TrimSpace(string(hmacData)), "\n")
				if len(lines) != 3 {
					ts.Fatalf("invalid HMAC file format: got %d lines", len(lines))
				}
				hmacEmail := lines[0]
				hmacTs := lines[1]
				hmacSig := lines[2]

				if hmacEmail != email {
					ts.Fatalf("email mismatch: expected %s, got %s", email, hmacEmail)
				}

				// Call setkey endpoint with HMAC token
				setkeyForm := fmt.Sprintf("email=%s&sig=%s&ts=%s&pubkey=%s",
					url.QueryEscape(email),
					url.QueryEscape(hmacSig),
					hmacTs,
					url.QueryEscape(pubkey))

				resp, err = http.Post(serverURL+"/setkey", "application/x-www-form-urlencoded", strings.NewReader(setkeyForm))
				if err != nil {
					ts.Fatalf("failed to set key: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					ts.Fatalf("setkey failed: %s - %s", resp.Status, string(body))
				}
			},
		},
	}
	testscript.Run(t, p)
}
