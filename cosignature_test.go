package torchwood_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/mldsa"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

func TestSignerRoundtrip(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testSignerRoundtrip(t, k, true)
	})
	t.Run("ML-DSA", func(t *testing.T) {
		k, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatal(err)
		}
		testSignerRoundtrip(t, k, false)
	})
}

func testSignerRoundtrip(t *testing.T, k crypto.Signer, extensions bool) {
	s, err := torchwood.NewCosignatureSigner("example.com", k)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	if extensions {
		msg += "extension 1\nextension 2\n"
	}
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	if !extensions {
		_, err := note.Sign(&note.Note{Text: msg + "extension 1\n"}, s)
		if err == nil {
			t.Fatal("expected error signing note with extension, got nil")
		}
	}

	if _, err := note.Open(n, note.VerifierList(s.Verifier())); err != nil {
		t.Fatal(err)
	}

	if extensions {
		nn := bytes.Replace(n, []byte("extension 2"), []byte("extension X"), 1)
		if _, err := note.Open(nn, note.VerifierList(s.Verifier())); err == nil {
			t.Fatal("expected error verifying modified note, got nil")
		}
	} else {
		nn := bytes.Replace(n, []byte("123"), []byte("124"), 1)
		if _, err := note.Open(nn, note.VerifierList(s.Verifier())); err == nil {
			t.Fatal("expected error verifying modified note, got nil")
		}

		nn = append(n, []byte("extension 1\n")...)
		if _, err := note.Open(nn, note.VerifierList(s.Verifier())); err == nil {
			t.Fatal("expected error verifying note with extra extension, got nil")
		}
	}

	v, err := torchwood.NewCosignatureVerifier(s.Verifier().String())
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != s.Verifier().String() {
		t.Fatalf("verifier string = %q; want %q", v.String(), s.Verifier().String())
	}
	if v.Name() != "example.com" {
		t.Fatalf("verifier name = %q; want %q", v.Name(), "example.com")
	}
	if v.KeyHash() != s.Verifier().KeyHash() {
		t.Fatalf("verifier hash = %d; want %d", v.KeyHash(), s.Verifier().KeyHash())
	}
	if _, err := note.Open(n, note.VerifierList(v)); err != nil {
		t.Fatal(err)
	}

	if extensions {
		nn := bytes.Replace(n, []byte("extension 2"), []byte("extension X"), 1)
		if _, err := note.Open(nn, note.VerifierList(v)); err == nil {
			t.Fatal("expected error verifying modified note, got nil")
		}
	} else {
		nn := bytes.Replace(n, []byte("123"), []byte("124"), 1)
		if _, err := note.Open(nn, note.VerifierList(v)); err == nil {
			t.Fatal("expected error verifying modified note, got nil")
		}

		nn = append(n, []byte("extension 1\n")...)
		if _, err := note.Open(nn, note.VerifierList(v)); err == nil {
			t.Fatal("expected error verifying note with extra extension, got nil")
		}
	}
}
