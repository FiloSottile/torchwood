package torchwood

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// FormatProof formats a tlog record inclusion proof (a "spicy signature") for
// the record at index idx with proof p and signed checkpoint signedCheckpoint.
//
// The returned byte slice is encoded according to c2sp.org/tlog-proof@v1.
func FormatProof(idx int64, p tlog.RecordProof, signedCheckpoint []byte) []byte {
	return formatProof(idx, p, signedCheckpoint, nil, false)
}

// FormatProofWithExtraData formats a tlog record inclusion proof (a "spicy
// signature") for the record at index idx with proof p and signed checkpoint
// signedCheckpoint, including extra data.
//
// The returned byte slice is encoded according to c2sp.org/tlog-proof@v1.
func FormatProofWithExtraData(idx int64, extra []byte, p tlog.RecordProof, signedCheckpoint []byte) []byte {
	return formatProof(idx, p, signedCheckpoint, extra, true)
}

func formatProof(idx int64, p tlog.RecordProof, signedCheckpoint []byte, extra []byte, withExtra bool) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "c2sp.org/tlog-proof@v1\n")
	if withExtra {
		fmt.Fprintf(&buf, "extra %s\n", base64.StdEncoding.EncodeToString([]byte(extra)))
	}
	fmt.Fprintf(&buf, "index %d\n", idx)
	for _, h := range p {
		fmt.Fprintf(&buf, "%s\n", h)
	}
	fmt.Fprintf(&buf, "\n")
	buf.Write(signedCheckpoint)
	return buf.Bytes()
}

// VerifyRecordError is returned by [VerifyProof] when the inclusion proof does
// not verify. It can be used to diagnose the issue or print a better error
// message. All of its fields are unauthenticated and must not be trusted.
type VerifyRecordError struct {
	Index int64
	Extra []byte
}

func (e *VerifyRecordError) Error() string {
	return fmt.Sprintf("tlog record inclusion proof verification failed for index %d", e.Index)
}

// VerifyProof verifies a proof (a "spicy signature" encoded according to
// c2sp.org/tlog-proof@v1) for a record hash rh (generally produced with
// [tlog.RecordHash]).
//
// The origin must match the log's origin, and the open function will be used to
// verify the signed checkpoint included in the proof. If open returns an error,
// it is returned directly. If the proof is valid but does not verify the record
// hash rh at the given index, a *[VerifyRecordError] is returned.
func VerifyProof(origin string, open func([]byte) (*note.Note, error), rh tlog.Hash, proof []byte) error {
	hdr, rest, ok := strings.Cut(string(proof), "\n")
	if !ok || hdr != "c2sp.org/tlog-proof@v1" {
		return errors.New("malformed tlog proof: missing header, this may not be a tlog proof")
	}
	var extra []byte
	if rest, ok = strings.CutPrefix(rest, "extra "); ok {
		var s string
		s, rest, ok = strings.Cut(rest, "\n")
		if !ok {
			return errors.New("malformed tlog proof: unexpected end of extra line")
		}
		var err error
		extra, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("malformed tlog proof: invalid extra: %w", err)
		}
	}
	rest, ok = strings.CutPrefix(rest, "index ")
	if !ok {
		return errors.New("malformed tlog proof: expected index line")
	}
	s, rest, ok := strings.Cut(rest, "\n")
	if !ok {
		return errors.New("malformed tlog proof: unexpected end of index line")
	}
	idx, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("malformed tlog proof: invalid index: %w", err)
	}
	if idx < 0 {
		return fmt.Errorf("malformed tlog proof: negative index")
	}
	var p tlog.RecordProof
	for {
		var h64 string
		h64, rest, ok = strings.Cut(rest, "\n")
		if !ok {
			return errors.New("malformed tlog proof: unexpected end of proof lines")
		}
		if h64 == "" {
			break
		}
		h, err := base64.StdEncoding.DecodeString(h64)
		if err != nil {
			return fmt.Errorf("malformed tlog proof: invalid hash: %w", err)
		}
		if len(h) != tlog.HashSize {
			return fmt.Errorf("malformed tlog proof: invalid hash length: got %d, want 32", len(h))
		}
		p = append(p, tlog.Hash(h))
	}
	// Peek at the origin, if it's wrong, opening will likely fail.
	if s, _, _ := strings.Cut(rest, "\n"); s != origin {
		return fmt.Errorf("proof origin mismatch: got %q, want %q", s, origin)
	}
	n, err := open([]byte(rest))
	if err != nil {
		return err
	}
	c, err := ParseCheckpoint(n.Text)
	if err != nil {
		return fmt.Errorf("invalid checkpoint in proof: %w", err)
	}
	if c.Origin != origin {
		return fmt.Errorf("checkpoint origin mismatch: got %q, want %q", c.Origin, origin)
	}
	if err := tlog.CheckRecord(p, c.N, c.Hash, idx, rh); err != nil {
		return &VerifyRecordError{
			Index: idx,
			Extra: extra,
		}
	}
	return nil
}

// ProofExtraData extracts the extra data from a tlog proof encoded according to
// c2sp.org/tlog-proof@v1. If no extra data is present, it returns an error.
//
// The extra data is unauthenticated and must not be trusted.
func ProofExtraData(proof []byte) ([]byte, error) {
	hdr, rest, ok := strings.Cut(string(proof), "\n")
	if !ok || hdr != "c2sp.org/tlog-proof@v1" {
		return nil, errors.New("malformed tlog proof: missing header, this may not be a tlog proof")
	}
	line, _, ok := strings.Cut(rest, "\n")
	if !ok {
		return nil, errors.New("malformed tlog proof: unexpected end of proof")
	}
	s, ok := strings.CutPrefix(line, "extra ")
	if !ok {
		return nil, errors.New("tlog proof does not contain extra data")
	}
	extra, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed tlog proof: invalid extra: %w", err)
	}
	return extra, nil
}
