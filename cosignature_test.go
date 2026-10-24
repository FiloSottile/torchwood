package torchwood_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
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

func TestSubtreeRawRoundtrip(t *testing.T) {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner("witness.example/w1", k)
	if err != nil {
		t.Fatal(err)
	}
	v := s.Verifier()

	th := tlog.RecordHash([]byte("test"))
	sig, err := s.SignSubtreeRaw("example.com/log", 8, 13, th)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("raw signature is %d bytes, want %d", len(sig), mldsa.MLDSA44SignatureSize)
	}

	if !v.VerifySubtreeRaw("example.com/log", 8, 13, th, sig) {
		t.Fatal("signature did not verify")
	}

	if v.VerifySubtreeRaw("example.com/other", 8, 13, th, sig) {
		t.Fatal("expected failure verifying wrong origin")
	}
	if v.VerifySubtreeRaw("example.com/log", 8, 12, th, sig) {
		t.Fatal("expected failure verifying wrong range")
	}
	if v.VerifySubtreeRaw("example.com/log", 4, 12, th, sig) {
		t.Fatal("expected failure verifying invalid subtree")
	}
	th2 := tlog.RecordHash([]byte("test2"))
	if v.VerifySubtreeRaw("example.com/log", 8, 13, th2, sig) {
		t.Fatal("expected failure verifying wrong hash")
	}

	tampered := bytes.Clone(sig)
	tampered[len(tampered)-1] ^= 1
	if v.VerifySubtreeRaw("example.com/log", 8, 13, th, tampered) {
		t.Fatal("expected failure verifying tampered signature")
	}
	if v.VerifySubtreeRaw("example.com/log", 8, 13, th, append(bytes.Clone(sig), 0)) {
		t.Fatal("expected failure verifying signature with trailing data")
	}
	if v.VerifySubtreeRaw("example.com/log", 8, 13, th, sig[:len(sig)-1]) {
		t.Fatal("expected failure verifying truncated signature")
	}

	// The signature commits to the cosigner name, so a different cosigner with
	// the same key doesn't verify it.
	s2, err := torchwood.NewCosignatureSigner("witness.example/w2", k)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Verifier().VerifySubtreeRaw("example.com/log", 8, 13, th, sig) {
		t.Fatal("expected failure verifying with another cosigner name")
	}

	// A raw signature is the last part of the deprecated note signature
	// encoding, without key hash and timestamp.
	line, err := s.SignSubtree("example.com/log", 8, 13, th)
	if err != nil {
		t.Fatal(err)
	}
	b64, ok := strings.CutPrefix(strings.TrimSuffix(string(line), "\n"), "— witness.example/w1 ")
	if !ok {
		t.Fatalf("unexpected signature line: %q", line)
	}
	noteSig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifySubtreeRaw("example.com/log", 8, 13, th, noteSig[4+8:]) {
		t.Fatal("raw part of note signature did not verify")
	}

	// A raw signature over the whole tree, prefixed with the key hash and a
	// zero timestamp, is a valid checkpoint cosignature.
	checkpoint := "example.com/log\n123\n" + base64.StdEncoding.EncodeToString(th[:]) + "\n"
	rootSig, err := s.SignSubtreeRaw("example.com/log", 0, 123, th)
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifySubtreeRaw("example.com/log", 0, 123, th, rootSig) {
		t.Fatal("root subtree signature did not verify")
	}
	rootNoteSig := binary.BigEndian.AppendUint32(nil, v.KeyHash())
	rootNoteSig = binary.BigEndian.AppendUint64(rootNoteSig, 0)
	rootNoteSig = append(rootNoteSig, rootSig...)
	signed := checkpoint + "\n— witness.example/w1 " + base64.StdEncoding.EncodeToString(rootNoteSig) + "\n"
	if _, err := note.Open([]byte(signed), note.VerifierList(v)); err != nil {
		t.Fatalf("root subtree signature did not verify as checkpoint cosignature: %v", err)
	}

	// The raw part of a checkpoint cosignature with a non-zero timestamp is
	// not a valid subtree cosignature.
	n, err := note.Sign(&note.Note{Text: checkpoint}, s)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := note.Open(n, note.VerifierList(v))
	if err != nil {
		t.Fatal(err)
	}
	if ts, err := torchwood.CosignatureTimestamp(opened.Sigs[0]); err != nil || ts == 0 {
		t.Fatalf("unexpected checkpoint cosignature timestamp %d: %v", ts, err)
	}
	checkpointSig, err := base64.StdEncoding.DecodeString(opened.Sigs[0].Base64)
	if err != nil {
		t.Fatal(err)
	}
	if v.VerifySubtreeRaw("example.com/log", 0, 123, th, checkpointSig[4+8:]) {
		t.Fatal("expected failure verifying raw part of checkpoint cosignature")
	}

	// Ed25519 keys can't sign or verify subtrees.
	_, ek, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := torchwood.NewCosignatureSigner("witness.example/ed", ek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.SignSubtreeRaw("example.com/log", 8, 13, th); err == nil {
		t.Fatal("expected error signing subtree with Ed25519 key")
	}
	if es.Verifier().VerifySubtreeRaw("example.com/log", 8, 13, th, sig) {
		t.Fatal("expected failure verifying with Ed25519 key")
	}

	// Empty subtrees can be signed and verified, but only with the hash of the
	// empty string.
	empty, err := tlog.TreeHash(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptySig, err := s.SignSubtreeRaw("example.com/log", 5, 5, empty)
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifySubtreeRaw("example.com/log", 5, 5, empty, emptySig) {
		t.Fatal("empty subtree signature did not verify")
	}
	if _, err := s.SignSubtreeRaw("example.com/log", 5, 5, th); err == nil {
		t.Fatal("expected error signing empty subtree with wrong hash")
	}
	if v.VerifySubtreeRaw("example.com/log", 5, 5, th, emptySig) {
		t.Fatal("expected failure verifying empty subtree with wrong hash")
	}
}

func TestSubtreeRoundtrip(t *testing.T) {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner("witness.example/w1", k)
	if err != nil {
		t.Fatal(err)
	}
	v := s.Verifier()

	th := tlog.RecordHash([]byte("test"))
	sig, err := s.SignSubtree("example.com/log", 8, 13, th)
	if err != nil {
		t.Fatal(err)
	}

	if !v.VerifySubtree("example.com/log", 8, 13, th, sig) {
		t.Fatal("signature did not verify")
	}

	if v.VerifySubtree("example.com/other", 8, 13, th, sig) {
		t.Fatal("expected failure verifying wrong origin")
	}
	if v.VerifySubtree("example.com/log", 8, 12, th, sig) {
		t.Fatal("expected failure verifying wrong range")
	}
	if v.VerifySubtree("example.com/log", 4, 12, th, sig) {
		t.Fatal("expected failure verifying invalid subtree")
	}
	th2 := tlog.RecordHash([]byte("test2"))
	if v.VerifySubtree("example.com/log", 8, 13, th2, sig) {
		t.Fatal("expected failure verifying wrong hash")
	}

	// A tampered signature doesn't verify.
	line, ok := strings.CutPrefix(strings.TrimSuffix(string(sig), "\n"), "— witness.example/w1 ")
	if !ok {
		t.Fatalf("unexpected signature line: %q", sig)
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	tampered := []byte("— witness.example/w1 " + base64.StdEncoding.EncodeToString(raw) + "\n")
	if v.VerifySubtree("example.com/log", 8, 13, th, tampered) {
		t.Fatal("expected failure verifying tampered signature")
	}

	// A signature line from another key doesn't verify, and multi-line
	// inputs are rejected.
	k2, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := torchwood.NewCosignatureSigner("witness.example/w2", k2)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := s2.SignSubtree("example.com/log", 8, 13, th)
	if err != nil {
		t.Fatal(err)
	}
	if v.VerifySubtree("example.com/log", 8, 13, th, sig2) {
		t.Fatal("expected failure verifying another witness's signature")
	}
	both := append(append([]byte{}, sig2...), sig...)
	if v.VerifySubtree("example.com/log", 8, 13, th, both) {
		t.Fatal("expected failure verifying multi-line input")
	}

	// Ed25519 keys can't sign or verify subtrees.
	_, ek, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := torchwood.NewCosignatureSigner("witness.example/ed", ek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.SignSubtree("example.com/log", 8, 13, th); err == nil {
		t.Fatal("expected error signing subtree with Ed25519 key")
	}
	if es.Verifier().VerifySubtree("example.com/log", 8, 13, th, sig) {
		t.Fatal("expected failure verifying with Ed25519 key")
	}

	// An ML-DSA checkpoint cosignature verifies as a cosignature over the
	// whole tree.
	checkpoint := "example.com/log\n123\n" + base64.StdEncoding.EncodeToString(th[:]) + "\n"
	n, err := note.Sign(&note.Note{Text: checkpoint}, s)
	if err != nil {
		t.Fatal(err)
	}
	_, checkpointSig, ok := strings.Cut(string(n), "\n\n")
	if !ok {
		t.Fatalf("unexpected note: %q", n)
	}
	if !v.VerifySubtree("example.com/log", 0, 123, th, []byte(checkpointSig)) {
		t.Fatal("checkpoint cosignature did not verify as subtree cosignature")
	}

	// Empty subtrees can be signed and verified, but only with the hash of the
	// empty string.
	empty, err := tlog.TreeHash(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptySig, err := s.SignSubtree("example.com/log", 5, 5, empty)
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifySubtree("example.com/log", 5, 5, empty, emptySig) {
		t.Fatal("empty subtree signature did not verify")
	}
	if _, err := s.SignSubtree("example.com/log", 5, 5, th); err == nil {
		t.Fatal("expected error signing empty subtree with wrong hash")
	}
	if v.VerifySubtree("example.com/log", 5, 5, th, emptySig) {
		t.Fatal("expected failure verifying empty subtree with wrong hash")
	}

	// A checkpoint for an empty tree can be cosigned, but only with the hash
	// of the empty string.
	emptyCheckpoint := "example.com/log\n0\n" + base64.StdEncoding.EncodeToString(empty[:]) + "\n"
	if _, err := note.Sign(&note.Note{Text: emptyCheckpoint}, s); err != nil {
		t.Fatal(err)
	}
	badEmptyCheckpoint := "example.com/log\n0\n" + base64.StdEncoding.EncodeToString(th[:]) + "\n"
	if _, err := note.Sign(&note.Note{Text: badEmptyCheckpoint}, s); err == nil {
		t.Fatal("expected error signing empty-tree checkpoint with wrong hash")
	}
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
