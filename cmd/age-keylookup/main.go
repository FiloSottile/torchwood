package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"filippo.io/mostly-harmless/vrf-r255"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	defaultKeyserverURL    = "https://keyserver.geomys.org"
	defaultKeyserverPubkey = "keyserver.geomys.org+16b31509+ARLJ+pmTj78HzTeBj04V+LVfB+GFAQyrg54CRIju7Nn8"
	defaultKeyserverVRFKey = "mKPsDHDcVB95iPXW4Yc7+HPfi3xOw/bHFvfWw6CAMBs="
)

func main() {
	allFlag := flag.Bool("all", false, "list all public keys in the transparency log")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: age-keylookup [-all] <email>\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Look up an age public key by email address.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "With -all, it enumerates all public keys in the transparency log.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  age-keylookup filippo@example.com\n")
		fmt.Fprintf(os.Stderr, "  age -r $(age-keylookup filippo@example.com) -o secret.txt.age secret.txt\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Environment:\n")
		fmt.Fprintf(os.Stderr, "  AGE_KEYSERVER_URL     Default keyserver URL\n")
		fmt.Fprintf(os.Stderr, "  AGE_KEYSERVER_PUBKEY  Default keyserver transparency log vkey\n")
		fmt.Fprintf(os.Stderr, "  AGE_KEYSERVER_VRFKEY  Default keyserver transparency log VRF public key\n")
		os.Exit(2)
	}

	email := flag.Arg(0)

	// Determine server URL
	server := os.Getenv("AGE_KEYSERVER_URL")
	if server == "" {
		server = defaultKeyserverURL
	}

	vkey := os.Getenv("AGE_KEYSERVER_PUBKEY")
	if vkey == "" {
		vkey = defaultKeyserverPubkey
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid keyserver public key: %v\n", err)
		os.Exit(1)
	}
	policy := torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(v.Name()), torchwood.SingleVerifierPolicy(v))

	vrfKeyB64 := os.Getenv("AGE_KEYSERVER_VRFKEY")
	if vrfKeyB64 == "" {
		vrfKeyB64 = defaultKeyserverVRFKey
	}
	vrfKeyBytes, err := base64.StdEncoding.DecodeString(vrfKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid base64 keyserver VRF public key: %v\n", err)
		os.Exit(1)
	}
	vrfKey, err := vrf.NewPublicKey(vrfKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid keyserver VRF public key: %v\n", err)
		os.Exit(1)
	}

	// Normalize email
	email = strings.TrimSpace(strings.ToLower(email))

	if *allFlag {
		pubkeys, err := monitorLog(server, policy, vrfKey, email)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, pk := range pubkeys {
			fmt.Println(pk)
		}
		return
	}

	pubkey, err := lookupKey(server, policy, vrfKey, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(pubkey)
}

func lookupKey(serverURL string, policy torchwood.Policy, vrfKey *vrf.PublicKey, email string) (string, error) {
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
		Proof  string `json:"proof"`
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

	// Compute and verify VRF hash
	vrfProofBytes, err := torchwood.ProofExtraData([]byte(result.Proof))
	if err != nil {
		return "", fmt.Errorf("failed to extract VRF proof: %w", err)
	}
	vrfProof, err := vrf.NewProof(vrfProofBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse VRF proof: %w", err)
	}
	vrfHash, err := vrfKey.Verify(vrfProof, []byte(email))
	if err != nil {
		return "", fmt.Errorf("failed to verify VRF proof: %w", err)
	}

	// Verify spicy signature
	h := sha256.New()
	h.Write([]byte(result.Pubkey))
	entry := h.Sum(vrfHash) // vrf-r255(email) || SHA-256(pubkey)
	if err := torchwood.VerifyProof(policy, tlog.RecordHash(entry), []byte(result.Proof)); err != nil {
		return "", fmt.Errorf("failed to verify key proof: %w", err)
	}

	return result.Pubkey, nil
}

func monitorLog(serverURL string, policy torchwood.Policy, vrfKey *vrf.PublicKey, email string) ([]string, error) {
	// Request the VRF proof and history from the monitor endpoint
	monitorURL := serverURL + "/api/monitor?email=" + url.QueryEscape(email)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(monitorURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to keyserver: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no key found for %s", email)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("keyserver error: %s - %s", resp.Status, string(body))
	}
	var result struct {
		Email    string   `json:"email"`
		VRFProof []byte   `json:"vrf_proof"`
		History  []string `json:"history"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Email != email {
		return nil, fmt.Errorf("keyserver returned unexpected email: %q", result.Email)
	}

	// Prepare map of hashes of historical keys
	historyHashes := make(map[[32]byte]string)
	for _, pk := range result.History {
		h := sha256.Sum256([]byte(pk))
		historyHashes[h] = pk
	}

	// Compute and verify VRF hash
	vrfProof, err := vrf.NewProof(result.VRFProof)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VRF proof: %w", err)
	}
	vrfHash, err := vrfKey.Verify(vrfProof, []byte(email))
	if err != nil {
		return nil, fmt.Errorf("failed to verify VRF proof: %w", err)
	}

	f, err := torchwood.NewTileFetcher(serverURL+"/tlog", torchwood.WithUserAgent("age-keylookup/1.0"))
	if err != nil {
		return nil, fmt.Errorf("failed to create tile fetcher: %w", err)
	}
	c, err := torchwood.NewClient(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create torchwood client: %w", err)
	}

	// Fetch and verify checkpoint
	signedCheckpoint, err := f.ReadEndpoint(context.Background(), "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	checkpoint, _, err := torchwood.VerifyCheckpoint(signedCheckpoint, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	// Fetch all entries up to the checkpoint size
	var pubkeys []string
	for i, entry := range c.AllEntries(context.Background(), checkpoint.Tree, 0) {
		if len(entry) != 64+32 {
			return nil, fmt.Errorf("invalid entry size at index %d", i)
		}
		if !bytes.Equal(entry[:64], vrfHash) {
			continue
		}
		pk, ok := historyHashes[([32]byte)(entry[64:])]
		if !ok {
			return nil, fmt.Errorf("found unknown public key hash in log at index %d", i)
		}
		pubkeys = append(pubkeys, pk)
	}
	if c.Err() != nil {
		return nil, fmt.Errorf("error fetching log entries: %w", c.Err())
	}

	return pubkeys, nil
}
