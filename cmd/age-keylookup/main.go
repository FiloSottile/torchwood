package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	defaultKeyserverURL = "https://keyserver.geomys.org"
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: age-keylookup <email>\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Look up an age public key by email address.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  age-keylookup filippo@example.com\n")
		fmt.Fprintf(os.Stderr, "  age -r $(age-keylookup filippo@example.com) -o secret.txt.age secret.txt\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Environment:\n")
		fmt.Fprintf(os.Stderr, "  AGE_KEYSERVER_URL     Default keyserver URL\n")
		os.Exit(2)
	}

	email := flag.Arg(0)

	// Determine server URL
	server := os.Getenv("AGE_KEYSERVER_URL")
	if server == "" {
		server = defaultKeyserverURL
	}

	pubkey, err := lookupKey(server, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(pubkey)
}

func lookupKey(serverURL, email string) (string, error) {
	// Build the lookup URL
	lookupURL := serverURL + "/api/lookup?email=" + url.QueryEscape(email)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Get(lookupURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect to keyserver: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("no key found for %s", email)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keyserver error: %s - %s", resp.Status, string(body))
	}

	// Parse JSON response
	var result struct {
		Email  string `json:"email"`
		Pubkey string `json:"pubkey"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Email != email {
		return "", fmt.Errorf("keyserver returned unexpected email: %q", result.Email)
	}
	if result.Pubkey == "" {
		return "", fmt.Errorf("empty public key returned")
	}

	return result.Pubkey, nil
}
