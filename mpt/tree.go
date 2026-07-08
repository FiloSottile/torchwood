// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mpt implements a Merkle Patricia Tree.
//
// A Merkle Patricia Tree (MPT) is a map that stores key-value pairs, where
// each key and value is an opaque value (often a SHA256 hash).
// Analogous to a [transparent log], an MPT can cryptographically prove
// that a given key-value pair exists (or that a key does not exist) in a given tree snapshot.
// By recording the sequence of tree snapshots in a transparent log,
// a server can publish a record of the history of a key-value database,
// enabling auditors to check that the database was correct at all times,
// while allowing clients to be sure the responses they received
// came from the recorded database history.
//
// To use the package, see the [Tree] interface, the [New] and [Create] constructors,
// and the [Verify] function.
// The rest of this doc comment describes the tree and proof encodings
// in enough detail to build an alternate wire-compatible implementation.
//
// # Tree Format
//
// The tree format used in this package is as follows.
//
// Conceptually, start with a complete [binary trie] of arbitrary height H,
// where H is larger than the number of bits in any key to be stored.
// Each key-value pair is placed in the tree at the node reached by
// starting at the root of the tree and following a path making
// left or right turns according to successive key bits and ends with
// however many left turns are needed to reach the leaf level
// (more precisely, the number of trailing left turns is H minus the key size in bits).
// Now we apply two optimizations to that binary radix tree.
//
// First, the tree is “path-compressed,” by removing inner nodes with a single child:
// a node that would have pointed at a single-child node
// is replaced by its child, recursively.
// Every node is therefore either a leaf or an inner node with two children.
// The path compression ensures that there are exactly N inner nodes for a tree with N+1 leaf nodes,
// and it makes the height of the tree depend only on the specific set of keys,
// not on the arbitrary height H.
//
// Second, unlike in a normal binary tree, an inner node stores only the bit position
// that determines whether a lookup should proceed to the left or right child.
// A lookup walks inner nodes down to some leaf, checking one bit at each step.
// Only upon reaching the leaf does it do a full key comparison.
// If it takes O(K) time to compare two keys, a normal binary tree would
// take O(K log N) time for a walk; this optimization
// cuts the time to O(K + log N).
// Furthermore, inner nodes need not store associated keys,
// cutting the number of stored keys by a factor of two.
//
// The path-compression optimization implies that an inner node for key prefix P exists
// if and only if the tree contains at least one key with prefix P||0 and at least one key with prefix P||1.
// That is, the specific inner nodes that exist in a tree depend only on which
// keys are present in the tree, not on their insertion order.
// This implies that we can batch or otherwise reorder insertions of distinct keys
// without affecting the final tree structure.
//
// Although this package does not yet support them, the tree structure
// described here supports keys of varying length.
// However, in such a tree, a lookup for a short key may need to compare
// additional bits to distinguish the short key from a longer key with
// the short key as a prefix. In this case, we define that a key of L bytes
// is treated as if padded with a 0x00 byte at position L followed by 0xFF bytes
// in all subsequent positions.
// The 0x00 byte means that, for text keys without NULs,
// short keys sort before their longer extensions.
// The subsequent 0xFF bytes ensure that two distinct keys never have
// the same padded bit sequence, even when one key is a prefix of the other.
//
// # Tree Snapshots
//
// A tree snapshot is defined as the hash of a tree, defined as follows, where H = SHA256.
//
//   - The hash of an empty tree is the hash of an empty (zero-length) input (e3b0c442...7852b855).
//   - The hash of a leaf node is the hash of a zero byte followed by the length-prefixed key and length-prefixed value: H(0 || len(key) || key || len(val) || val).
//   - The hash of an inner node is the hash a one byte followed by the node's bit position and its left and right children's hashes: H(1 || bit || left-hash || right-hash).
//
// The lengths and bit position are [varint-encoded], so that most are one byte.
//
// Notice that the hash of a node representing a subtree is the same
// as the hash of a tree containing only those nodes: the root node is not special.
// Although this package does not make use of that fact, it does mean that a
// large MPT could be split across multiple computers.
//
// # Proofs
//
// A proof cryptographically attests to a claim about the
// presence or absence of a specific key in a specific tree snapshot.
// The claim takes one of two forms:
//
//   - The snapshot contains a specific key-value pair.
//   - The snapshot does not contain a specific key.
//
// In this package, a claim and proof are returned by the [Tree.Prove] method,
// and the caller is expected to have already used the [Tree.Snapshot] method
// to obtain the snapshot.
// A verifier (possibly on another system) can then pass the snapshot,
// claim, and proof to [Verify] to cryptographically verify the claim.
//
// The proof only contains the supplemental information needed for verification.
// It does not include the snapshot or the claim, so the proof can only be checked
// with respect to a specific snapshot and claim.
// In fact, a single proof may be valid for many (snapshot, claim) pairs.
//
// The specific form of the proof depends on which of three cases is being proved.
//
//  1. If the snapshot is for an empty tree, the proof is empty (zero length).
//     It proves any claim that a key is not present.
//
//  2. If the claim is that a specific key-value pair is present in a snapshot,
//     then the proof is a concatenation of zero or more (bit, sibling hash) pairs
//     giving the path from the key-value leaf node up to the root of the tree.
//     The verifier computes the leaf hash from the key and value
//     and then computes the hashes of successive parent nodes up to the root,
//     checking that the final hash matches the snapshot.
//     At each parent node, the key's specified bit position indicates whether
//     the hash computed so far is the left or right child hash.
//     The sibling hash provides the other.
//     In the proof encoding, the bit positions are [varint-encoded].
//
//  3. If the claim is that a specific key is not present in a non-empty snapshot,
//     then a lookup for key in the tree must instead end at some pair altkey-altval,
//     where altkey ≠ key. The proof consists of the altkey-altval pair, including
//     varint-encoded length prefixes, followed by the proof that altkey-altval
//     is in the tree (as in case 2).
//     The verifier proceeds as in case 2 to confirm that altkey-altval is in the snapshot.
//     Along the way, it must also check that key and altkey agree at every bit position
//     in the path, confirming that the lookup for key would indeed end at altkey instead.
//
// For a tree storing N-bit keys, the longest existence proof is N-1 (bit, sibling hash) pairs,
// while the longest non-existence proof is a key, a value, and N (bit, sibling hash) pairs.
// In both cases the worst case length is dominated by the hashes, about 32N bytes.
// A tree using random keys (for example, using SHA256 hashes as keys)
// would of course never reach this maximum length for any sizable N.
//
// Note that this encoding is considerably more compact than some others.
// In particular, the [Rust akd crate's MembershipProof] includes the inner node key
// and sibling key for each step in the path, tripling the size of the proofs.
//
// [binary trie]: https://en.wikipedia.org/wiki/Trie
// [transparent log]: https://research.swtch.com/tlog
// [varint-encoded]: https://protobuf.dev/programming-guides/encoding/#varints
// [Rust akd crate's MembershipProof]: https://docs.rs/akd/0.12.0/akd/struct.MembershipProof.html
package mpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"math/bits"
)

// A Tree is a Merkle Patricia Tree implementation.
type Tree interface {
	// Set adds the given key-value pair to the tree.
	// If there is already an entry for the given key,
	// then val replaces the old value.
	//
	// Set is a mutating operation and must not be called
	// concurrently with any other Tree method calls
	// (including other calls to Set).
	Set(key Key, val Val) error

	// Predict returns the hash of the tree that would result from
	// applying the given changes (sorted by key) to the tree,
	// without modifying the tree.
	//
	// It is an error to call Predict with changes that are not
	// sorted by increasing key or that contain duplicate keys.
	// Implementations may return [ErrInvalidPredict] in this case.
	//
	// It is an error to call Predict if Set has been called without
	// a subsequent call to Snap: in that case, the caller does not
	// know what the current hash is.
	Predict(changes []KeyVal) (Hash, error)

	// Snap sets the tree's version number and returns the current tree snapshot.
	//
	// Snap is a mutating operation and must not be called
	// concurrently with any other Tree method calls
	// (including other calls to Snap).
	//
	// As a special case, if version is negative, Snap does not
	// set the version.
	Snap(version int64) (Snapshot, error)

	// Prove looks up key in the tree and returns a claimed
	// associated value (if any) and whether the key is present at all,
	// along with a proof of those two claimed results.
	// Use [Verify] to verify the proof before trusting the claims.
	//
	// If Prove returns normally (with err == nil), then proof is non-nil,
	// although it may be empty.
	//
	// If Prove returns a non-nil error error, then val is Val{},
	// ok is false, and proof is nil.
	//
	// Prove is a read-only operation and can be called
	// concurrently with other calls to Prove, but not other
	// calls to Set or Snap.
	//
	// It is an error to call Prove if Set has been called without
	// a subsequent call to Snap: in that case, the caller does not
	// know what the root hash is, so the proof will be unverifiable.
	Prove(key Key) (val Val, ok bool, proof Proof, err error)

	// Sync flushes all changes from past Set and Snap calls to
	// the underlying files and then calls the files' Sync methods
	// to flush the changes to disk. (If the files are *os.File files,
	// Sync calls fsync(2).)
	//
	// Sync must not be called concurrently with other calls to Sync
	// or (as noted above) with calls to Set.
	//
	// Even in the absence of calls to Sync, a Tree provides the
	// guarantee that on recovery from a crash, it can identify the
	// latest snapshot whose Set calls are fully included in the tree.
	// A client can call Version() to find the stored tree's version V
	// and a boolean indicating whether any later Set calls may also
	// be reflected in the tree. When a recovered version is inexact,
	// some Set calls made after that version may be present and
	// others may not be, no matter the order in which the Set calls were made.
	Sync() error

	// Version returns the version number of the tree's last complete snapshot.
	// All Set calls made prior to Snap(version) are guaranteed to be
	// recorded in the tree. However, if exact is false, then the tree may
	// include the effect of Set calls made after that snapshot.
	// In that case, to bring the tree into a consistent state, the client is
	// expected to replay all Set calls up to the next version.
	Version() (version int64, exact bool)

	// Close calls Sync and then closes the underlying files.
	Close() error
}

// ErrModifiedTree indicates that Prove was called after a Set without a Snap.
var ErrModifiedTree = errors.New("tree modified without snapshot")

// ErrInvalidPredict indicates that Predict was passed a set of
// changes that was not sorted by Key.Compare, contained
// duplicates, or had a key or value that was too large
// (more than [MaxKeyLen] or [MaxValLen] bytes).
var ErrInvalidPredict = errors.New("invalid predicted changes")

func checkChanges(changes []KeyVal) error {
	for _, c := range changes {
		if len(c.Key) > MaxKeyLen || len(c.Val) > MaxValLen {
			return ErrInvalidPredict
		}
	}
	for i := 0; i < len(changes)-1; i++ {
		if changes[i].Key.Compare(changes[i+1].Key) >= 0 {
			return ErrInvalidPredict
		}
	}
	return nil
}

// A Key is a key used by a Tree.
// It is usually a cryptographic hash of the actual key data.
// A Key can be at most MaxKeyLen bytes.
type Key []byte

const (
	// MaxKeyLen is the maximum length of a Key
	// that can be stored in a Tree.
	// Attempts to use larger keys return [ErrKeySize].
	MaxKeyLen = 1024

	// MaxValLen is the maximum length of a Val
	// that can be stored in a Tree.
	// Attempts to use larger values return [ErrValSize].
	MaxValLen = 1024
)

// maxKeyBits is the longest possible key length we need to consider,
// including padding. The +1 is because a key of MaxKeyLen bytes
// ending in 0x00 and its MaxKeyLen-1-byte prefix only differ when
// you consider the padding beyond MaxKeyLen.
const maxKeyBits = MaxKeyLen*8 + 1

var (
	// ErrKeySize reports use of a key larger than [MaxKeyLen] bytes.
	ErrKeySize = errors.New("key too large")

	// ErrValSize reports use of a value larger than [MaxValLen] bytes.
	ErrValSize = errors.New("val too large")
)

func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// bit returns the n'th bit of the key.
func (k Key) bit(n int) int {
	return bit(k, n)
}

// cmp compares p and q (using key + infinite padding 00 FF FF FF...)
// and returns the comparison result c (-1, 0, +1) and the number of
// leading bits p and q have in common (overlap).
func (p Key) cmp(q Key) (c, overlap int) {
	short, long, fix := p, q, +1
	if len(short) > len(long) {
		short, long, fix = long, short, -fix
	}
	for i := range short {
		pf := short[i]
		qf := long[i]
		if pf != qf {
			overlap := i*8 + bits.LeadingZeros8(pf^qf)
			c := -1
			if pf > qf {
				c = +1
			}
			return c * fix, overlap
		}
	}
	if len(short) == len(long) {
		return 0, maxKeyBits
	}
	// short is a prefix of long.
	// short's padding starts with 0x00 at len(short), followed by 0xFF, 0xFF...
	// Compare short's padding byte 0x00 with long[len(short)].
	b0 := long[len(short)]
	if b0 != 0x00 {
		// 0x00 vs b0 (where b0 > 0x00 since long[len(short)] != 0)
		overlap := len(short)*8 + bits.LeadingZeros8(b0)
		c := -1 // short (0x00) < long (b0)
		return c * fix, overlap
	}
	// Both have 0x00 at position len(short).
	// Padding for short continues as FF FF FF...
	for i := len(short) + 1; i < len(long); i++ {
		if long[i] != 0xFF {
			// 0xFF vs long[i]
			overlap := i*8 + bits.LeadingZeros8(0xFF^long[i])
			c := +1 // short (0xFF) > long (long[i] < 0xFF)
			return c * fix, overlap
		}
	}
	// long matches short's padding through all of long's bytes.
	// Now compare padding at len(long):
	// short has 0xFF (continued padding).
	// long has 0x00 (start of long's padding).
	// So short (0xFF) > long (0x00).
	c = +1
	return c * fix, len(long) * 8
}

// overlap returns the number of leading bits p and q have in common.
func (p Key) overlap(q Key) int {
	_, overlap := p.cmp(q)
	return overlap
}

// Compare returns the result of comparing two keys,
// using the order in which the keys will appear in a [Tree].
// Compare often agrees with [bytes.Compare].
// In particular it is the same as [bytes.Compare] when
// keys have fixed length, when no key can be a prefix of another,
// or when keys do not contain NUL bytes.
// In the general case, however, Compare returns
// bytes.Compare(k+pad, k2+pad) where pad is the infinite byte sequence “00 FF FF FF...”.
func (p Key) Compare(q Key) int {
	c, _ := p.cmp(q)
	return c
}

// A Val is a value stored in a Tree.
// It is usually a cryptographic hash of the actual value data.
type Val []byte

func (v Val) String() string {
	return hex.EncodeToString(v[:])
}

// KeyVal is a key-value pair.
type KeyVal struct {
	Key Key
	Val Val
}

// Compare returns the result of comparing keys kv.Key and other.Key.
// It ignores the Val fields.
func (kv KeyVal) Compare(other KeyVal) int {
	return kv.Key.Compare(other.Key)
}

// A keyPrefix is a prefix of a key, identifying a specific node.
type keyPrefix struct {
	// bits is the prefix length in bits (0..maxKeyBits, inclusive).
	bits int

	// full is the key whose prefix is being taken.
	full Key
}

func (p keyPrefix) String() string {
	n := (p.bits + 7) / 8
	if n > len(p.full) {
		n = len(p.full)
	}
	return fmt.Sprintf("%x/%d", p.full[:n], p.bits)
}

// overlap returns the number of leading bits p and q have in common.
func (p keyPrefix) overlap(q keyPrefix) int {
	return min(p.bits, q.bits, p.full.overlap(q.full))
}

func (p keyPrefix) truncate(bits int) keyPrefix {
	p.bits = bits
	return p
}

func (p keyPrefix) compare(q keyPrefix) int {
	if p.bits != q.bits {
		panic(fmt.Sprintf("keyPrefix.compare mismatched bits: %d != %d", p.bits, q.bits))
	}
	c, overlap := p.full.cmp(q.full)
	if overlap >= p.bits {
		return 0
	}
	return c
}

func prefix(key Key, bits int) keyPrefix {
	return keyPrefix{bits: bits, full: key}
}

// A node represents the metadata for a single node.
type node struct {
	key  keyPrefix
	hash Hash
}

func (x node) merge(y node) node {
	b := x.key.overlap(y.key)
	return node{x.key.truncate(b), hashInner(b, x.hash, y.hash)}
}

// A Snapshot is a cryptographic snapshot of a Tree at a point in time.
// It is expected that every snapshot is recorded in a transparent log.
//
// The snapshot epoch is a sequence number identifying a specific snapshot.
// An empty Tree has epoch 0, and then the epoch is incremented each
// time a new snapshot is created (by calling [Tree.Snap] after new records
// are added).
//
// The snapshot hash is a cryptographic hash of the entire tree content.
type Snapshot struct {
	Version int64
	Hash    Hash
}

// A Hash is a Merkle hash of a node.
type Hash [32]byte

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// TreeHash computes the snapshot hash of a tree consisting of
// the sequence of key-value items.
//
// The sequence must be sorted by increasing
// key value (such as by [Key.Compare] or [KeyVal.Compare]),
// and a key cannot appear multiple times in the list.
// TreeHash panics if the sequence is not sorted or a key appears twice.
//
// Use [slices.Values] to apply TreeHash to a slice of KeyVal.
func TreeHash(seq iter.Seq[KeyVal]) Hash {
	var s []node
	for kv := range seq {
		s = reduce(append(s, node{prefix(kv.Key, maxKeyBits), hashLeaf(kv.Key, kv.Val)}))
	}
	return hashStack(s)
}

// A Proof is a proof of the result of looking up a target key in a
// specific snapshot of a Tree.
type Proof []byte

var (
	// ErrInvalidProof indicates that a proof is not valid for the claimed result.
	ErrInvalidProof = errors.New("invalid mpt proof")

	// ErrInvalidLookup indicates that ok is false but val is non-empty.
	ErrInvalidLookup = errors.New("invalid mpt lookup result")
)

// Verify verifies that p is a valid proof that a lookup for key in snap
// should return the result (val, ok).
// If the proof is not valid, Verify returns a non-nil error.
//
// [VerifyPresent] and [VerifyNotPresent] are convenience functions
// that wrap Verify.
func Verify(snap Snapshot, key, val []byte, ok bool, proof Proof) error {
	if !ok && len(val) != 0 {
		return ErrInvalidLookup
	}
	if !ok && len(proof) == 0 {
		if snap.Hash == emptyTreeHash() {
			return nil
		}
		return ErrInvalidProof
	}

	var pkey []byte
	var h Hash
	if ok {
		pkey = key
		h = hashLeaf(key, val)
	} else {
		var pval []byte
		var ok bool
		pkey, proof, ok = cutVar(proof)
		if !ok {
			return ErrInvalidProof
		}
		pval, proof, ok = cutVar(proof)
		if !ok {
			return ErrInvalidProof
		}
		if bytes.Equal(pkey, key) {
			return ErrInvalidProof
		}
		h = hashLeaf(pkey, pval)
	}

	b := 1 << 30
	for len(proof) > 0 {
		ub, n := binary.Uvarint(proof)
		if n <= 0 || ub >= uint64(b) {
			break
		}
		b = int(ub)
		proof = proof[n:]
		if len(proof) < 32 {
			return ErrInvalidProof
		}
		var sib Hash
		sib, proof = Hash(proof[:32]), proof[32:]
		if bit(key, b) != bit(pkey, b) {
			return ErrInvalidProof
		}
		if bit(key, b) == 0 {
			h = hashInner(b, h, sib)
		} else {
			h = hashInner(b, sib, h)
		}
	}
	if len(proof) != 0 || h != snap.Hash {
		return ErrInvalidProof
	}
	return nil
}

// VerifyPresent is shorthand for [Verify](snap, key[:], val[:], true, proof).
func VerifyPresent(snap Snapshot, key Key, val Val, proof Proof) error {
	return Verify(snap, key[:], val[:], true, proof)
}

// VerifyNotPresent is shorthand for [Verify](snap, key[:], nil, false, proof).
func VerifyNotPresent(snap Snapshot, key Key, proof Proof) error {
	return Verify(snap, key[:], nil, false, proof)
}

// bit returns the n'th bit of the byte slice b, extended with padding.
// A key is padded with a 0x00 byte followed by arbitrarily many 0xFF bytes.
func bit(b []byte, n int) int {
	i := n >> 3
	if i < len(b) {
		return (int(b[i]) >> (7 - n&7)) & 1
	}
	if i == len(b) {
		return 0
	}
	return 1
}

// emptyTreeHash returns the parent hash for a root no child nodes.
func emptyTreeHash() Hash {
	h := sha256.Sum256(nil)
	return h
}

// hashLeaf returns the hash of a leaf with a given key and value,
// where key and val are variable-length byte slices.
// The hash is H(0 || len(key) || key || len(val) || val),
// where the lengths are varint-encoded.
func hashLeaf(key Key, val Val) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(key)))
	h.Write(buf[:n])
	h.Write(key)
	n = binary.PutUvarint(buf[:], uint64(len(val)))
	h.Write(buf[:n])
	h.Write(val)
	return Hash(h.Sum(nil))
}

// hashInner returns the hash of an inner node
// with the given bit position and left and right child hashes.
// The hash is H(1 || bit || left-hash || right-hash),
// where the bit is varint-encoded.
func hashInner(b int, left, right Hash) Hash {
	var buf [1 + binary.MaxVarintLen64 + 32 + 32]byte
	buf[0] = 1
	n := 1
	n += binary.PutUvarint(buf[n:], uint64(b))
	n += copy(buf[n:], left[:])
	n += copy(buf[n:], right[:])
	return sha256.Sum256(buf[:n])
}

// cutVar cuts a varint-length-prefixed value from the start of data,
// returning the value and the rest of the data.
func cutVar(data []byte) (value, rest []byte, ok bool) {
	x, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, nil, false
	}
	data = data[n:]
	if uint64(len(data)) < x {
		return nil, nil, false
	}
	return data[:x], data[x:], true
}

func reduce(s []node) []node {
	for len(s) >= 3 && s[len(s)-3].key.overlap(s[len(s)-2].key) > s[len(s)-2].key.overlap(s[len(s)-1].key) {
		m := s[len(s)-3].merge(s[len(s)-2])
		s = append(s[:len(s)-3], m, s[len(s)-1])
	}
	return s
}

func hashStack(s []node) Hash {
	if len(s) == 0 {
		return emptyTreeHash()
	}
	for len(s) >= 2 {
		s = append(s[:len(s)-2], s[len(s)-2].merge(s[len(s)-1]))
	}
	return s[0].hash
}
