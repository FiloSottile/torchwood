package torchwood_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// setupTestLog creates a test log with a signer/verifier and returns them
// along with a signed checkpoint for a log with the given size and tree hash.
func setupTestLog(t *testing.T, origin string, size int64, hash tlog.Hash) (note.Signer, note.Verifier, []byte) {
	t.Helper()

	// Generate a test key using note.GenerateKey
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	checkpoint := torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: size, Hash: hash},
	}

	signedCheckpoint, err := note.Sign(&note.Note{Text: checkpoint.String()}, signer)
	if err != nil {
		t.Fatalf("failed to sign checkpoint: %v", err)
	}

	return signer, verifier, signedCheckpoint
}

func TestFormatProof(t *testing.T) {
	origin := "example.com/test"
	hash := tlog.RecordHash([]byte("test data"))

	// Create a simple proof
	proof := tlog.RecordProof{
		tlog.RecordHash([]byte("hash1")),
		tlog.RecordHash([]byte("hash2")),
	}

	_, _, signedCheckpoint := setupTestLog(t, origin, 10, hash)

	formatted := torchwood.FormatProof(5, proof, signedCheckpoint)

	// Check that it starts with the header
	if !bytes.HasPrefix(formatted, []byte("c2sp.org/tlog-proof@v1\n")) {
		t.Errorf("formatted proof missing header")
	}

	// Check that it contains the index
	if !bytes.Contains(formatted, []byte("index 5\n")) {
		t.Errorf("formatted proof missing index")
	}

	// Check that it does NOT contain a extra line
	if bytes.Contains(formatted, []byte("extra ")) {
		t.Errorf("formatted proof should not contain extra")
	}

	// Check that it contains the proof hashes
	for _, h := range proof {
		if !bytes.Contains(formatted, []byte(base64.StdEncoding.EncodeToString(h[:]))) {
			t.Errorf("formatted proof missing hash %x", h)
		}
	}

	// Check that it contains the checkpoint
	if !bytes.Contains(formatted, signedCheckpoint) {
		t.Errorf("formatted proof missing signed checkpoint")
	}
}

func TestFormatProofWithExtra(t *testing.T) {
	origin := "example.com/test"
	hash := tlog.RecordHash([]byte("test data"))
	extra := []byte("test-extra-data")

	proof := tlog.RecordProof{
		tlog.RecordHash([]byte("hash1")),
	}

	_, _, signedCheckpoint := setupTestLog(t, origin, 10, hash)

	formatted := torchwood.FormatProofWithExtraData(3, extra, proof, signedCheckpoint)

	// Check that it starts with the header
	if !bytes.HasPrefix(formatted, []byte("c2sp.org/tlog-proof@v1\n")) {
		t.Errorf("formatted proof missing header")
	}

	// Check that it contains the index
	if !bytes.Contains(formatted, []byte("index 3\n")) {
		t.Errorf("formatted proof missing index")
	}

	// Check that it contains the extra
	expectedExtra := "extra " + base64.StdEncoding.EncodeToString(extra) + "\n"
	if !bytes.Contains(formatted, []byte(expectedExtra)) {
		t.Errorf("formatted proof missing or incorrect extra, got %s", formatted)
	}

	// Check that it contains the checkpoint
	if !bytes.Contains(formatted, signedCheckpoint) {
		t.Errorf("formatted proof missing signed checkpoint")
	}
}

func TestVerifyProof_Valid(t *testing.T) {
	origin := "example.com/test"
	data := []byte("test data for verification")
	recordHash := tlog.RecordHash(data)

	// Build a simple tree with one record
	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	// Add one record to the tree
	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	_, verifier, signedCheckpoint := setupTestLog(t, origin, 1, treeHash)

	// Generate proof for record 0
	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// Format the proof
	formattedProof := torchwood.FormatProof(0, proof, signedCheckpoint)

	// Verify the proof
	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier))
	}

	err = torchwood.VerifyProof(origin, openFunc, recordHash, formattedProof)
	if err != nil {
		t.Errorf("VerifyProof failed for valid proof: %v", err)
	}
}

func TestVerifyProof_ValidWithExtra(t *testing.T) {
	origin := "example.com/test"
	data := []byte("test data")
	extra := []byte("my-extra")
	recordHash := tlog.RecordHash(data)

	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	_, verifier, signedCheckpoint := setupTestLog(t, origin, 1, treeHash)

	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	formattedProof := torchwood.FormatProofWithExtraData(0, extra, proof, signedCheckpoint)

	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier))
	}

	err = torchwood.VerifyProof(origin, openFunc, recordHash, formattedProof)
	if err != nil {
		t.Errorf("VerifyProof failed for valid proof with extra: %v", err)
	}
}

func TestVerifyProof_MissingHeader(t *testing.T) {
	proof := []byte("index 0\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for missing header")
	}
	if !strings.Contains(err.Error(), "missing header") {
		t.Errorf("expected 'missing header' error, got: %v", err)
	}
}

func TestVerifyProof_InvalidHeader(t *testing.T) {
	proof := []byte("wrong-header\nindex 0\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for invalid header")
	}
	if !strings.Contains(err.Error(), "missing header") {
		t.Errorf("expected 'missing header' error, got: %v", err)
	}
}

func TestVerifyProof_MissingIndex(t *testing.T) {
	proof := []byte("c2sp.org/tlog-proof@v1\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for missing index")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected 'malformed' error, got: %v", err)
	}
}

func TestVerifyProof_InvalidIndex(t *testing.T) {
	proof := []byte("c2sp.org/tlog-proof@v1\nindex notanumber\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for invalid index")
	}
	if !strings.Contains(err.Error(), "invalid index") {
		t.Errorf("expected 'invalid index' error, got: %v", err)
	}
}

func TestVerifyProof_NegativeIndex(t *testing.T) {
	proof := []byte("c2sp.org/tlog-proof@v1\nindex -1\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for negative index")
	}
	if !strings.Contains(err.Error(), "negative index") {
		t.Errorf("expected 'negative index' error, got: %v", err)
	}
}

func TestVerifyProof_InvalidExtra(t *testing.T) {
	proof := []byte("c2sp.org/tlog-proof@v1\nextra not-valid-base64!!!\nindex 0\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for invalid extra encoding")
	}
	if !strings.Contains(err.Error(), "invalid extra") {
		t.Errorf("expected 'invalid extra' error, got: %v", err)
	}
}

func TestVerifyProof_InvalidHash(t *testing.T) {
	proof := []byte("c2sp.org/tlog-proof@v1\nindex 0\nnot-valid-base64!!!\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for invalid hash encoding")
	}
	if !strings.Contains(err.Error(), "invalid hash") {
		t.Errorf("expected 'invalid hash' error, got: %v", err)
	}
}

func TestVerifyProof_InvalidHashLength(t *testing.T) {
	// Create a base64-encoded hash that's too short (16 bytes instead of 32)
	shortHash := base64.StdEncoding.EncodeToString(make([]byte, 16))
	proof := []byte(fmt.Sprintf("c2sp.org/tlog-proof@v1\nindex 0\n%s\n\nexample.com/test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", shortHash))

	openFunc := func(msg []byte) (*note.Note, error) {
		return nil, errors.New("should not be called")
	}

	err := torchwood.VerifyProof("example.com/test", openFunc, tlog.Hash{}, proof)
	if err == nil {
		t.Error("VerifyProof should fail for invalid hash length")
	}
	if !strings.Contains(err.Error(), "invalid hash length") {
		t.Errorf("expected 'invalid hash length' error, got: %v", err)
	}
}

func TestVerifyProof_OriginMismatch(t *testing.T) {
	origin := "example.com/test"
	wrongOrigin := "wrong.com/test"

	// Create a valid-looking proof with wrong origin
	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	data := []byte("test")
	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	// Create checkpoint with wrong origin
	_, verifier, signedCheckpoint := setupTestLog(t, wrongOrigin, 1, treeHash)

	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	formattedProof := torchwood.FormatProof(0, proof, signedCheckpoint)

	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier))
	}

	err = torchwood.VerifyProof(origin, openFunc, tlog.RecordHash(data), formattedProof)
	if err == nil {
		t.Error("VerifyProof should fail for origin mismatch")
	}
	if !strings.Contains(err.Error(), "origin mismatch") {
		t.Errorf("expected 'origin mismatch' error, got: %v", err)
	}
}

func TestVerifyProof_SignatureVerificationFails(t *testing.T) {
	origin := "example.com/test"

	// Create a valid proof structure but with a bad signature
	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	data := []byte("test")
	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	// Create two different signers
	_, verifier1, signedCheckpoint := setupTestLog(t, origin, 1, treeHash)
	_, verifier2, _ := setupTestLog(t, origin, 1, treeHash)

	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	formattedProof := torchwood.FormatProof(0, proof, signedCheckpoint)

	// Try to verify with the wrong verifier
	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier2))
	}

	err = torchwood.VerifyProof(origin, openFunc, tlog.RecordHash(data), formattedProof)
	if err == nil {
		t.Error("VerifyProof should fail when signature verification fails")
	}

	// Verify it works with the correct verifier
	openFunc = func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier1))
	}

	err = torchwood.VerifyProof(origin, openFunc, tlog.RecordHash(data), formattedProof)
	if err != nil {
		t.Errorf("VerifyProof should succeed with correct verifier: %v", err)
	}
}

func TestVerifyProof_RecordVerificationFails(t *testing.T) {
	origin := "example.com/test"
	data := []byte("correct data")
	wrongData := []byte("wrong data")

	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	// Build tree with correct data
	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	_, verifier, signedCheckpoint := setupTestLog(t, origin, 1, treeHash)

	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	formattedProof := torchwood.FormatProof(0, proof, signedCheckpoint)

	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier))
	}

	// Try to verify with wrong data
	err = torchwood.VerifyProof(origin, openFunc, tlog.RecordHash(wrongData), formattedProof)
	if err == nil {
		t.Error("VerifyProof should fail when record hash doesn't match")
	}

	// Check that it returns a VerifyRecordError
	var verifyErr *torchwood.VerifyRecordError
	if !errors.As(err, &verifyErr) {
		t.Errorf("expected VerifyRecordError, got: %T", err)
	} else {
		if verifyErr.Index != 0 {
			t.Errorf("expected Index=0, got Index=%d", verifyErr.Index)
		}
		if len(verifyErr.Extra) != 0 {
			t.Errorf("expected empty Extra, got Extra=%q", verifyErr.Extra)
		}
	}
}

func TestVerifyRecordError_WithExtra(t *testing.T) {
	origin := "example.com/test"
	data := []byte("correct data")
	wrongData := []byte("wrong data")
	extra := []byte("test-extra")

	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		var result []tlog.Hash
		for _, idx := range indexes {
			if idx < 0 || idx >= int64(len(hashes)) {
				return nil, fmt.Errorf("hash index %d out of range", idx)
			}
			result = append(result, hashes[idx])
		}
		return result, nil
	})

	newHashes, err := tlog.StoredHashes(0, data, hashReader)
	if err != nil {
		t.Fatalf("failed to compute stored hashes: %v", err)
	}
	hashes = append(hashes, newHashes...)

	treeHash, err := tlog.TreeHash(1, hashReader)
	if err != nil {
		t.Fatalf("failed to compute tree hash: %v", err)
	}

	_, verifier, signedCheckpoint := setupTestLog(t, origin, 1, treeHash)

	proof, err := tlog.ProveRecord(1, 0, hashReader)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	formattedProof := torchwood.FormatProofWithExtraData(0, extra, proof, signedCheckpoint)

	openFunc := func(msg []byte) (*note.Note, error) {
		return note.Open(msg, note.VerifierList(verifier))
	}

	err = torchwood.VerifyProof(origin, openFunc, tlog.RecordHash(wrongData), formattedProof)
	if err == nil {
		t.Error("VerifyProof should fail when record hash doesn't match")
	}

	// Check that it returns a VerifyRecordError with the extra
	var verifyErr *torchwood.VerifyRecordError
	if !errors.As(err, &verifyErr) {
		t.Errorf("expected VerifyRecordError, got: %T", err)
	} else {
		if verifyErr.Index != 0 {
			t.Errorf("expected Index=0, got Index=%d", verifyErr.Index)
		}
		if !bytes.Equal(verifyErr.Extra, extra) {
			t.Errorf("expected Extra=%q, got Extra=%q", extra, verifyErr.Extra)
		}
		expectedMsg := "tlog record inclusion proof verification failed for index 0"
		if verifyErr.Error() != expectedMsg {
			t.Errorf("expected error message %q, got %q", expectedMsg, verifyErr.Error())
		}
	}
}
