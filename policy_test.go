package torchwood_test

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestParsePolicyLogKey(t *testing.T) {
	origin := "example.com/log"
	checkpoint := torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: 123, Hash: tlog.RecordHash([]byte("test data"))},
	}

	t.Run("Ed25519", func(t *testing.T) {
		skey, vkey, err := note.GenerateKey(rand.Reader, origin)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := note.NewSigner(skey)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := note.Sign(&note.Note{Text: checkpoint.String()}, signer)
		if err != nil {
			t.Fatal(err)
		}

		policy, err := torchwood.ParsePolicy([]byte("log " + vkey + "\nquorum none\n"))
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := torchwood.VerifyCheckpoint(signed, policy)
		if err != nil {
			t.Fatal(err)
		}
		if c.Origin != origin {
			t.Errorf("origin = %q; want %q", c.Origin, origin)
		}
	})

	t.Run("ML-DSA", func(t *testing.T) {
		k, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatal(err)
		}
		signer, err := torchwood.NewCosignatureSigner(origin, k)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := note.Sign(&note.Note{Text: checkpoint.String()}, signer)
		if err != nil {
			t.Fatal(err)
		}

		policy, err := torchwood.ParsePolicy([]byte("log " + signer.Verifier().String() + "\nquorum none\n"))
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := torchwood.VerifyCheckpoint(signed, policy)
		if err != nil {
			t.Fatal(err)
		}
		if c.Origin != origin {
			t.Errorf("origin = %q; want %q", c.Origin, origin)
		}

		// A checkpoint for a different origin doesn't satisfy the policy, even
		// if the signature verifies.
		other := torchwood.Checkpoint{
			Origin: "example.com/other",
			Tree:   checkpoint.Tree,
		}
		signedOther, err := note.Sign(&note.Note{Text: other.String()}, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := torchwood.VerifyCheckpoint(signedOther, policy); err == nil {
			t.Error("expected error verifying checkpoint with wrong origin")
		}
	})

	t.Run("Ed25519 cosignature key rejected", func(t *testing.T) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := torchwood.NewCosignatureSigner(origin, k)
		if err != nil {
			t.Fatal(err)
		}
		_, err = torchwood.ParsePolicy([]byte("log " + signer.Verifier().String() + "\nquorum none\n"))
		if err == nil {
			t.Error("expected error parsing log line with Ed25519 cosignature vkey")
		}
	})
}

func TestParsePolicyMLDSAWithWitness(t *testing.T) {
	origin := "example.com/log"
	checkpoint := torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: 123, Hash: tlog.RecordHash([]byte("test data"))},
	}

	logKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := torchwood.NewCosignatureSigner(origin, logKey)
	if err != nil {
		t.Fatal(err)
	}
	witnessKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	witnessSigner, err := torchwood.NewCosignatureSigner("witness.example/w1", witnessKey)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := torchwood.ParsePolicy([]byte(
		"log " + logSigner.Verifier().String() + "\n" +
			"witness W1 " + witnessSigner.Verifier().String() + "\n" +
			"quorum W1\n"))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := note.Sign(&note.Note{Text: checkpoint.String()}, logSigner, witnessSigner)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := torchwood.VerifyCheckpoint(signed, policy)
	if err != nil {
		t.Fatal(err)
	}
	if c.Origin != origin {
		t.Errorf("origin = %q; want %q", c.Origin, origin)
	}

	// Without the witness cosignature, the quorum is not satisfied.
	signedLogOnly, err := note.Sign(&note.Note{Text: checkpoint.String()}, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := torchwood.VerifyCheckpoint(signedLogOnly, policy); err == nil {
		t.Error("expected error verifying checkpoint without witness cosignature")
	}
}
