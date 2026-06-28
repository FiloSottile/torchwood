// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package torchwood

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/mldsa"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

const (
	algCosignatureEd25519 = 4
	algCosignatureMLDSA   = 6
)

// NewCosignatureSigner constructs a new [CosignatureSigner] from an ML-DSA-44
// or Ed25519 private key.
//
// Note that ML-DSA-44 cosigners reject checkpoints with extension lines.
func NewCosignatureSigner(name string, key crypto.Signer) (*CosignatureSigner, error) {
	pubKey := key.Public()
	v, err := NewCosignatureVerifierFromKey(name, pubKey)
	if err != nil {
		return nil, err
	}
	s := &CosignatureSigner{v: *v}
	switch pubKey.(type) {
	case ed25519.PublicKey:
		s.sign = func(msg []byte) ([]byte, error) {
			t := uint64(time.Now().Unix())
			m, err := formatCosignatureV1(t, msg)
			if err != nil {
				return nil, err
			}
			s, err := key.Sign(nil, m, crypto.Hash(0))
			if err != nil {
				return nil, err
			}

			// The signature itself is encoded as timestamp || signature.
			sig := make([]byte, 0, 8+ed25519.SignatureSize)
			sig = binary.BigEndian.AppendUint64(sig, t)
			sig = append(sig, s...)
			return sig, nil
		}
	case *mldsa.PublicKey:
		s.sign = func(msg []byte) ([]byte, error) {
			t := uint64(time.Now().Unix())
			m, err := formatSubtreeV1(name, t, msg)
			if err != nil {
				return nil, err
			}
			s, err := key.Sign(nil, m, crypto.Hash(0))
			if err != nil {
				return nil, err
			}

			// The signature itself is encoded as timestamp || signature.
			sig := make([]byte, 0, 8+mldsa.MLDSA44SignatureSize)
			sig = binary.BigEndian.AppendUint64(sig, t)
			sig = append(sig, s...)
			return sig, nil
		}
	default:
		return nil, errors.New("key type is not supported")
	}
	return s, nil
}

func formatCosignatureV1(t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format
	//
	//      cosignature/v1
	//      time TTTTTTTTTT
	//      [checkpoint]
	//
	// where TTTTTTTTTT is the current UNIX timestamp.

	c, err := ParseCheckpoint(string(msg))
	if err != nil {
		return nil, fmt.Errorf("message being signed is not a valid checkpoint: %w", err)
	}
	if string(msg) != c.String() {
		return nil, errors.New("message being signed does not match parsed checkpoint")
	}
	return []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", t, msg)), nil
}

func formatSubtreeV1(name string, t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format
	//
	// struct {
	//     uint8 label[12] = "subtree/v1\n\0";
	//     opaque cosigner_name<1..2^8-1>;
	//     uint64 timestamp;
	//     opaque log_origin<1..2^8-1>;
	//     uint64 start;
	//     uint64 end;
	//     uint8 hash[32];
	// } cosigned_message;

	c, err := ParseCheckpoint(string(msg))
	if err != nil {
		return nil, fmt.Errorf("message being signed is not a valid checkpoint: %w", err)
	}
	// Unsigned extension lines are dangerous, for now don't support them,
	// unless and until someone suggests a good/safe use case.
	if c.Extension != "" {
		return nil, errors.New("ML-DSA cosignatures do not support checkpoints with extension lines")
	}
	if string(msg) != c.String() {
		return nil, errors.New("message being signed does not match parsed checkpoint")
	}
	b := &cryptobyte.Builder{}
	b.AddBytes([]byte("subtree/v1\n\x00"))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(name))
	})
	b.AddUint64(t)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(c.Origin))
	})
	b.AddUint64(0)
	b.AddUint64(uint64(c.N))
	b.AddBytes(c.Hash[:])
	return b.Bytes()
}

// CosignatureSigner is a [note.Signer] that produces timestamped
// cosignatures according to c2sp.org/tlog-cosignature.
type CosignatureSigner struct {
	v    CosignatureVerifier
	sign func([]byte) ([]byte, error)
}

func (s *CosignatureSigner) Name() string                    { return s.v.Name() }
func (s *CosignatureSigner) KeyHash() uint32                 { return s.v.KeyHash() }
func (s *CosignatureSigner) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }
func (s *CosignatureSigner) Verifier() *CosignatureVerifier  { return &s.v }

var _ note.Signer = &CosignatureSigner{}

// CosignatureVerifier is a [note.Verifier] that verifies cosignatures
// according to c2sp.org/tlog-cosignature.
type CosignatureVerifier struct {
	verifier
	key crypto.PublicKey
}

var _ note.Verifier = &CosignatureVerifier{}

// NewCosignatureVerifier constructs a new [CosignatureVerifier] from a
// c2sp.org/signed-note vkey string. It supports ML-DSA-44 and Ed25519 vkeys.
//
// Note that ML-DSA-44 verifiers reject cosignatures on checkpoints with
// extension lines.
func NewCosignatureVerifier(vkey string) (*CosignatureVerifier, error) {
	name, vkey, _ := strings.Cut(vkey, "+")
	hash16, key64, _ := strings.Cut(vkey, "+")
	hash, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if len(hash16) != 8 || err1 != nil || err2 != nil || len(key) == 0 {
		return nil, errors.New("malformed verifier id")
	}
	alg, key := key[0], key[1:]
	var verifier *CosignatureVerifier
	switch alg {
	case algCosignatureEd25519:
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("malformed verifier public key")
		}
		k := ed25519.PublicKey(key)
		v, err := NewCosignatureVerifierFromKey(name, k)
		if err != nil {
			return nil, err
		}
		verifier = v
	case algCosignatureMLDSA:
		k, err := mldsa.NewPublicKey(mldsa.MLDSA44(), key)
		if err != nil {
			return nil, fmt.Errorf("malformed verifier public key: %w", err)
		}
		v, err := NewCosignatureVerifierFromKey(name, k)
		if err != nil {
			return nil, err
		}
		verifier = v
	default:
		return nil, errors.New("unknown verifier algorithm")
	}
	if uint32(hash) != verifier.KeyHash() {
		return nil, errors.New("invalid verifier hash")
	}
	return verifier, nil
}

// NewCosignatureVerifierFromKey constructs a new [CosignatureVerifier] from a
// public key. It supports [ed25519.PublicKey] and [*mldsa.PublicKey].
//
// Note that ML-DSA-44 verifiers reject cosignatures on checkpoints with
// extension lines.
func NewCosignatureVerifierFromKey(name string, key crypto.PublicKey) (*CosignatureVerifier, error) {
	if !isValidName(name) {
		return nil, errors.New("invalid name")
	}

	switch k := key.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("malformed Ed25519 public key")
		}
		hash := keyHash(name, append([]byte{algCosignatureEd25519}, k...))
		return &CosignatureVerifier{
			verifier: verifier{
				name: name,
				hash: hash,
				verify: func(msg, sig []byte) bool {
					if len(sig) != 8+ed25519.SignatureSize {
						return false
					}
					t := binary.BigEndian.Uint64(sig)
					if t > math.MaxInt64 {
						return false
					}
					sig = sig[8:]
					m, err := formatCosignatureV1(t, msg)
					if err != nil {
						return false
					}
					return ed25519.Verify(k, m, sig)
				},
			},
			key: k,
		}, nil
	case *mldsa.PublicKey:
		if k.Parameters() != mldsa.MLDSA44() {
			return nil, errors.New("ML-DSA parameters are not ML-DSA-44")
		}
		hash := keyHash(name, append([]byte{algCosignatureMLDSA}, k.Bytes()...))
		return &CosignatureVerifier{
			verifier: verifier{
				name: name,
				hash: hash,
				verify: func(msg, sig []byte) bool {
					if len(sig) != 8+mldsa.MLDSA44SignatureSize {
						return false
					}
					t := binary.BigEndian.Uint64(sig)
					if t > math.MaxInt64 {
						return false
					}
					sig = sig[8:]
					m, err := formatSubtreeV1(name, t, msg)
					if err != nil {
						return false
					}
					return mldsa.Verify(k, m, sig, nil) == nil
				},
			},
			key: k,
		}, nil
	default:
		return nil, errors.New("key type is not supported")
	}
}

// PublicKey returns the [ed25519.PublicKey] or [*mldsa.PublicKey] of the
// verifier, depending on the algorithm.
func (v *CosignatureVerifier) PublicKey() crypto.PublicKey {
	return v.key
}

// String returns the vkey encoding of the verifier, according to
// c2sp.org/signed-note.
func (v *CosignatureVerifier) String() string {
	switch k := v.key.(type) {
	case ed25519.PublicKey:
		return fmt.Sprintf("%s+%08x+%s", v.name, v.hash, base64.StdEncoding.EncodeToString(
			append([]byte{algCosignatureEd25519}, k...)))
	case *mldsa.PublicKey:
		return fmt.Sprintf("%s+%08x+%s", v.name, v.hash, base64.StdEncoding.EncodeToString(
			append([]byte{algCosignatureMLDSA}, k.Bytes()...)))
	default:
		panic("unknown verifier key type")
	}
}

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

// CosignatureTimestamp returns the timestamp of the cosignature, which is the
// time at which the witness signed the checkpoint, in seconds since the Unix epoch.
//
// Witnesses can re-sign a checkpoint, but only if it's for the latest tree they
// have seen. Thus, the timestamp can be used to determine if a checkpoint is fresh.
func CosignatureTimestamp(sig note.Signature) (int64, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Base64)
	if err != nil {
		return 0, err
	}
	var timestamp uint64
	s := cryptobyte.String(sigBytes)
	if !s.Skip(4 /* key hash */) || !s.ReadUint64(&timestamp) ||
		timestamp > math.MaxInt64 {
		return 0, errors.New("malformed cosignature")
	}
	return int64(timestamp), nil
}
