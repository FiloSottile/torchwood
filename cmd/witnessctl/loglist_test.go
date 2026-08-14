package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"filippo.io/mldsa"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

func TestParseLogListAccepts(t *testing.T) {
	mldsaOrigin := "example.com/mldsa-log"
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	mldsaSigner, err := torchwood.NewCosignatureSigner(mldsaOrigin, mldsaKey)
	if err != nil {
		t.Fatal(err)
	}
	mldsaVkey := mldsaSigner.Verifier().String()

	_, edVkey, err := note.GenerateKey(rand.Reader, "example.com/ed25519-log")
	if err != nil {
		t.Fatal(err)
	}

	list := fmt.Sprintf(`
# Log list that should be accepted
logs/v0

# ML-DSA-44 log
vkey %s
qpd 24

  # should be ignored
unknown-key some-value
contact test@mldsa-log

# Ed25519 log
vkey %s
qpd 3600
contact test@ed25519-log
`, mldsaVkey, edVkey)
	logs, err := parseLogList([]byte(list), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Errorf("expected two logs, got: %d", len(logs))
	}
	if logs[mldsaOrigin] != mldsaVkey {
		t.Errorf("ML-DSA log not parsed: %v", logs)
	}
	if logs["example.com/ed25519-log"] != edVkey {
		t.Errorf("Ed25519 log not parsed: %v", logs)
	}
}

func TestParseLogListSkipsEd25519Cosignature(t *testing.T) {
	origin := "example.com/ed-cosig-log"
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := torchwood.NewCosignatureSigner(origin, k)
	if err != nil {
		t.Fatal(err)
	}
	vkey := signer.Verifier().String()

	list := fmt.Sprintf(`
logs/v0
vkey %s
qpd 24
contact test@ed25519-cosig
`, vkey)
	logs, err := parseLogList([]byte(list), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Errorf("expected Ed25519 cosignature log to be skipped, got: %v", logs)
	}
}
