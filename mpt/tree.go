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
// and the [VerifyLookup] function.
// The rest of this doc comment describes the tree and proof encodings
// in enough detail to build an alternate wire-compatible implementation.
//
// # Tree Format
//
// The tree format used in this package is as follows.
//
// Conceptually, start with a [binary trie] of arbitrary height H,
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
// Every node is therefore either a leaf or an inner node with two children
// whose keys agree until, but then differ at, bit position B.
// The inner node stores B and pointers to the two children.
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
// The prefix property also implies that for any given prefix P of some stored key K,
// the set of keys starting with prefix P form a distinct subtree of the tree
// rooted at the node corresponding to the longest common prefix shared
// by all those keys (which must in turn start with P).
// That subtree root node may be K's leaf, the overall tree root, or some inner
// node between them.
//
// The tree structure described here supports keys of varying length.
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
// (Padding with a single repeated byte would not ensure distinct
// extensions for distinct keys. For example, if the padding was
// all 0x00 bytes, then "ABC" and "ABC\x00" would look identical when padded.)
//
// # Tree Snapshots
//
// A tree snapshot is defined as the hash of a tree, defined as follows, where H = SHA256.
//
//   - The hash of an empty tree is the hash of an empty (zero-length) input (e3b0c442...7852b855).
//   - The hash of a leaf node is the hash of a zero byte followed by the length-prefixed key and length-prefixed value: H(0 || len(key) || key || len(val) || val).
//   - The hash of an inner node is the hash a one byte followed by the node's bit position B and its left and right children's hashes: H(1 || B || left-hash || right-hash).
//
// The lengths and bit position are [varint-encoded], so that most are one byte.
//
// Notice that the hash of a node representing a subtree is the same
// as the hash of a tree containing only those nodes: the root node is not special.
// Although this package does not make use of that fact, it does mean that a
// large MPT could be split across multiple computers.
//
// # Proofs and How to Verify Them
//
// A proof cryptographically attests to a claim about the
// presence or absence of a specific key or subtree
// in a specific tree snapshot.
// A verifier takes as input a snapshot tree hash,
// a claim, and a proof, and it checks whether the proof is valid.
//
// If a snapshot's tree hash is the empty tree hash (SHA256 of the empty input),
// then the tree is known to be empty, the proof is always an empty string,
// and verification consists of checking whether the claim is true of an empty tree.
// The rest of this discussion only considers claims about non-empty trees.
//
// The proofs and verification algorithms for specific claims are
// all derived from the following general form.
//
// A “path proof” consists of a key-val pair and then the bit index and
// sibling hash for each inner node from the key-val leaf up to
// the root:
//
//	len(key) || key || len(val) || val || B₁ || H₁ || B₂ || H₂ || ... || B_N || H_N
//
// (The bit indexes B_i must be strictly decreasing.)
//
// The path proof includes all the information necessary to recompute
// the overall tree hash:
//
//		hash = H(0 || len(key) || key || len(val) || val)
//		hash = H(1 || B₁ || hash || H₁) or H(1 || B₁ || H₁ || hash),
//	        depending on whether bit B₁ of key is 0 or 1
//		hash = H(1 || B₂ || hash || H₂) or H(1 || B₂ || H₂ || hash)
//		...
//		hash = H(1 || B_N || hash || H_N) or H(1 || B_N || H_N || hash)
//
// Note that bit at index B_i in the key determines whether H_i
// is the left or right input hash.
//
// “Path verification” is the process of computing the final hash
// from the path proof and checking that it matches the snapshot's
// tree hash. If it does, that proves that the snapshot includes
// key-val correctly indexed.
//
// For a tree storing N-bit keys, the longest possible path proof is a key, a value,
// and N (bit, sibling hash) pairs. That worst case length is dominated by the hashes,
// about 32N bytes. A tree using random keys (for example, using SHA256 hashes as keys)
// would of course never reach this maximum length for any sizable N.
//
// Note that this encoding is considerably more compact than some others.
// In particular, the [Rust akd crate's MembershipProof] includes the inner node key
// and sibling key for each step in the path, tripling the size of the proofs.
//
// # Key Proofs
//
// [Tree.Path](key) returns the path proof for key.
// The path ends at key's own leaf if key is in the tree
// and at a different leaf if it is not.
//
// [ProveLookup](key, path) reduces that path proof to (val, ok, proof),
// claiming either that the key does not appear in the tree (ok=false)
// or that it does appear with associated value val (ok=true).
// [VerifyLookup](snap, key, val, ok, proof) verifies the claim.
//
// To claim that a snapshot does not contain a specific key,
// the proof is the path proof for the alternate altkey-altval
// that would be reached by a lookup for key.
//
// To verify the claim, run path verification, check that
// altkey and key agree at every bit index B_i in the path,
// and check that altkey ≠ key. (Altkey and key must differ at some
// bit index not used in the path.)
//
// To claim that a snapshot contains a specific key-val pair,
// the proof is a path proof shortened by omitting key and val.
//
// To verify the claim, run path verification using the key
// and val passed to VerifyLookup.
//
// # Prefix Proofs
//
// [ProvePrefix](prefix, path) reduces the path proof returned by
// [Tree.Path](prefix) to (hash, proof), where hash is the
// hash of a (possibly empty) subtree containing all the keys in the
// tree that begin with prefix. [VerifyPrefix](snap, prefix, hash, proof)
// verifies the claim.
// Note that VerifyPrefix does not verify that the subtree
// is minimal. The verified subtree may also include keys with other prefixes.
// This subtlety is discussed in the next section.
//
// Let P be the number of bits in the prefix.
//
// To claim that a snapshot contains no keys with the prefix,
// the subtree hash is the empty tree hash, and the proof is the
// path proof for the altkey-altval reached by looking up
// prefix as if it were a key.
//
// To verify the claim, run path verification on the proof,
// check that altkey and the prefix (padded) agree at every bit index B_i
// in the path, and check that altkey (padded) does not start
// with prefix (unpadded). That is, altkey and prefix must differ at
// some bit index B < P not used in the path.
//
// Note: from the standpoint of strict correctness, it would suffice
// for the prover to choose and look up _any_ padding of prefix
// and for the verifier not to check that altkey's bits at indexes
// B ≥ P. However, this would create multiple correct answers
// for any particular ProvePrefix call, complicating conformance testing.
// We choose to require that prefix be padded like a key
// to force a specific answer from ProvePrefix and also to allow
// provers to reuse their key lookup logic.
// If there are no keys with prefix P in a tree,
// then the negative claims from ProveLookup(P) and ProvePrefix(P)
// share the same proof.
//
// To claim that a snapshot's subtree includes all keys with the prefix,
// the proof is a path proof corresponding to looking up prefix as a key,
// but the proof omits the steps that lead to the subtree hash.
// That is, the proof is:
//
//	B_k || H_k || B_{k+1} || H_{k+1} || ... || B_N || H_N
//
// To verify the claim, check that B_k < P (the subtree is not more
// specific than the prefix). Then assume that path verification
// up to B_k produced the subtree hash and complete the verification,
// walking the rest of the way to the root, using prefix bits to
// decide whether each H_i is a left or right sibling.
//
// # One-Sided Weakness of Prefix Proofs
//
// As noted above, this verification only proves that the subtree
// must contain all the keys starting with the prefix.
// The subtree may contain other keys as well. In the most extreme case,
// if hash = snap (claiming the entire tree as the subtree), then
//
//	VerifyPrefix(snap, prefix, hash, empty-proof)
//
// always succeeds, regardless of whether the tree is entirely keys
// starting with prefix, entirely keys not starting with prefix,
// or a mixture.
//
// Although a claim of too large a subtree will verify,
// a claim of too small a subtree (excluding some keys starting
// with the prefix) will not verify, because such a claim would
// have to split the key space beyond the prefix length
// by using B_k ≥ P, and the verifier checks B_k < P.
//
// The one-sided weakness of the claim is not a problem in practice,
// since to fully check the map, the caller must also obtain
// all the key-val pairs starting with prefix and use them to
// recompute the subtree hash. While doing that, the caller can also
// check that all the keys start with prefix. If they do, then
// the subtree is not too large.
//
// An alternate design would be to have ProvePrefix return the
// full path proof, checking that the subtree hash matches the
// reconstructed hash before the first B_k < P.
// However, these proofs would be longer for no practical benefit:
// the caller would still need to obtain the full key-val pair list
// to check the stored values.
//
// [Rust akd crate's MembershipProof]: https://docs.rs/akd/0.12.0/akd/struct.MembershipProof.html
// [binary trie]: https://en.wikipedia.org/wiki/Trie
// [transparent log]: https://research.swtch.com/tlog
// [varint-encoded]: https://protobuf.dev/programming-guides/encoding/#varints
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
	"slices"
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

	// Path returns the path proof for key in the tree.
	// If key is present in the tree, the path ends at key's own leaf.
	// Otherwise the path ends at the leaf holding the different key
	// where the lookup for key stopped.
	// If the tree is empty, the path proof is empty (but non-nil).
	//
	// Path is the raw material for the claims made by [ProveLookup] and
	// [ProvePrefix]: ProveLookup(key, path) reduces the path returned by
	// Path(key) to a key lookup claim and its proof, and
	// ProvePrefix(prefix, path) reduces the path returned by
	// Path(prefix) to a prefix claim and its proof.
	//
	// If Path returns successfully (with err == nil), then proof is non-nil,
	// although it may be empty. If Path returns a non-nil error,
	// then proof is nil.
	//
	// Path is a read-only operation and can be called
	// concurrently with other read-only calls and uses of iterators,
	// but not with calls to Set or Snap.
	//
	// It is an error to call Path if Set has been called without
	// a subsequent call to Snap: in that case, the caller does not
	// know what the root hash is, so the proof will be unverifiable.
	Path(key Key) (proof Proof, err error)

	// Scan returns an iterator over all key-value pairs in the tree
	// with the given prefix (according to [Key.HasPrefix]),
	// in key order (according to [Key.Compare]).
	//
	// While iterating, the slices in the returned KeyVal must not
	// be modified and are only valid during the iteration step in
	// which they are returned. The caller must clone them if they
	// need to be retained.
	//
	// Scan and the returned iterator are read-only operations
	// and can be called concurrently with other read-only calls
	// and uses of iterators, but not with calls to Set or Snap.
	Scan(prefix []byte) iter.Seq2[KeyVal, error]

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

// ErrModifiedTree indicates that Path was called after a Set without a Snap.
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
//
// For purposes of comparison (using [Key.Compare] and [Key.HasPrefix])
// a Key is considered to be an infinite stream that starts with the
// bytes in the slice and continues with the infinite byte sequence “00 FF FF FF...”
// (one 0x00 byte and then an infinite number of 0xFF bytes).
// This convention is necessary in general because the MPT data structure
// requires that no key be a prefix of another key except when the two keys are equal.
// However, the nuance can be ignored in two very common cases:
//
// - When all keys are the same length (for example, when keys are fixed-length hash outputs).
// - When all keys do not contain NUL bytes (for example, when keys are text).
//
// In both of these cases, [Key.Compare] and [Key.HasPrefix] are equivalent
// to [bytes.Compare] and [bytes.HasPrefix].
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

// String returns the key encoded in hexadecimal.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// Clone returns a copy of the key.
func (k Key) Clone() Key {
	return slices.Clone(k)
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
//
// Compare usually agrees with [bytes.Compare], but not always.
// See the [Key] documentation for more details.
func (k Key) Compare(other Key) int {
	c, _ := k.cmp(other)
	return c
}

// HasPrefix reports whether k begins with the given prefix.
//
// HasPrefix usually agrees with [bytes.HasPrefix], but not always.
// See the [Key] documentation for more details.
func (k Key) HasPrefix(prefix []byte) bool {
	return bytes.HasPrefix(k, prefix) ||
		len(prefix) > len(k) && bytes.Equal(prefix[:len(k)], k) && prefix[len(k)] == 0x00 && allFF(prefix[len(k)+1:])
}

// allFF reports whether b is all 0xFF bytes.
func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xFF {
			return false
		}
	}
	return true
}

// A Val is a value stored in a Tree.
// It is usually a cryptographic hash of the actual value data.
type Val []byte

func (v Val) String() string {
	return hex.EncodeToString(v[:])
}

// Clone returns a copy of the value.
func (v Val) Clone() Val {
	return slices.Clone(v)
}

// KeyVal is a key-value pair.
type KeyVal struct {
	Key Key
	Val Val
}

// CompareKey returns the result of comparing keys kv.Key and other.Key.
// It ignores the Val fields.
func (kv KeyVal) CompareKey(other KeyVal) int {
	return kv.Key.Compare(other.Key)
}

// Equal reports whether kv and other have equal keys and values.
func (kv KeyVal) Equal(other KeyVal) bool {
	return bytes.Equal(kv.Key, other.Key) && bytes.Equal(kv.Val, other.Val)
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

// EmptyTreeHash returns the hash of an empty tree.
// It is equal to TreeHash of an empty sequence.
func EmptyTreeHash() Hash {
	return emptyTreeHash
}

var emptyTreeHash Hash = sha256.Sum256(nil)

// TreeHash computes the snapshot hash of a tree consisting of
// the sequence of key-value items.
//
// The sequence must be sorted by increasing
// key value (such as by [Key.Compare] or [KeyVal.CompareKey]),
// and a key cannot appear multiple times in the list.
// TreeHash panics with ErrKeyOrder
// if the sequence is not sorted or a key appears twice.
//
// Use [slices.Values] to apply TreeHash to a slice of KeyVal.
func TreeHash(seq iter.Seq[KeyVal]) Hash {
	var s []node
	var last Key
	for kv := range seq {
		if last != nil && last.Compare(kv.Key) >= 0 {
			panic(ErrKeyOrder)
		}
		if last == nil {
			last = []byte{}
		}
		last = append(last[:0], kv.Key...)
		// TODO: Could be more careful about reusing key buffers in the node stack.
		s = reduce(append(s, node{prefix(kv.Key.Clone(), maxKeyBits), hashLeaf(kv.Key, kv.Val)}))
	}
	return hashStack(s)
}

// TreeHashErr computes the snapshot hash of a tree consisting of
// the sequence of key-value items.
//
// The sequence must be sorted by increasing
// key value (such as by [Key.Compare] or [KeyVal.CompareKey]),
// and a key cannot appear multiple times in the list.
// TreeHashErr returns ErrKeyOrder if the sequence is not sorted or a key appears twice.
// It also returns any error yielded by the iterator.
func TreeHashErr(seq iter.Seq2[KeyVal, error]) (Hash, error) {
	var s []node
	var last Key
	for kv, err := range seq {
		if err != nil {
			return Hash{}, err
		}
		if last != nil && last.Compare(kv.Key) >= 0 {
			return Hash{}, ErrKeyOrder
		}
		if last == nil {
			last = []byte{}
		}
		last = append(last[:0], kv.Key...)
		// TODO: Could be more careful about reusing key buffers in the node stack.
		s = reduce(append(s, node{prefix(kv.Key.Clone(), maxKeyBits), hashLeaf(kv.Key, kv.Val)}))
	}
	return hashStack(s), nil
}

// A Proof is a proof of the result of looking up a target key
// or key prefix in a specific snapshot of a Tree.
type Proof []byte

var (
	// ErrInvalidProof indicates that a proof is not valid for the claimed result.
	ErrInvalidProof = errors.New("invalid mpt proof")

	// ErrInvalidLookup indicates that ok is false but val is non-empty.
	ErrInvalidLookup = errors.New("invalid mpt lookup result")

	// ErrKeyOrder indicates that a KeyVal sequence is out of order
	// or contains duplicates.
	ErrKeyOrder = errors.New("mpt keys out of order")

	// ErrInvalidPath indicates that a path proof passed to [ProveLookup]
	// or [ProvePrefix] is not well-formed. This cannot happen for a
	// path returned by [Tree.Path].
	ErrInvalidPath = errors.New("invalid mpt path proof")
)

// ProveLookup reduces the path proof returned by [Tree.Path](key) to the
// claimed result of a lookup for key, along with a proof of that claim:
// either key is not in the tree (ok is false) or it is present with
// value val (ok is true). The proof can be verified with [VerifyLookup].
//
// ProveLookup returns an error only if path is malformed.
// That cannot happen for a path returned by Tree.Path.
func ProveLookup(key Key, path Proof) (val Val, ok bool, proof Proof, err error) {
	if len(path) == 0 {
		// Empty tree, so key is certainly not present.
		return nil, false, Proof{}, nil
	}
	pkey, pval, rest, wellFormed := cutPathLeafErr(path)
	if !wellFormed {
		return nil, false, nil, ErrInvalidPath
	}
	if !bytes.Equal(pkey, key) {
		// The lookup for key ended at a different key,
		// so key is not in the tree. The proof is the whole path,
		// including the alternate key-value pair.
		return nil, false, path, nil
	}
	// The lookup found key. [VerifyLookup] recomputes the leaf hash from the
	// key and val it is given, so the proof omits them.
	return pval, true, rest, nil
}

// ProvePrefix reduces the path proof returned by [Tree.Path](prefix) to a
// claimed tree hash for the subtree holding every key-value pair whose key
// starts with prefix, along with a proof of that claim.
// If no key starts with prefix, the claimed hash is [EmptyTreeHash].
// The proof can be verified with [VerifyPrefix].
//
// ProvePrefix returns an error only if path is malformed.
// That cannot happen for a path returned by Tree.Path.
func ProvePrefix(prefix []byte, path Proof) (Hash, Proof, error) {
	if len(path) == 0 {
		// Empty tree, so no key starts with prefix.
		return emptyTreeHash, Proof{}, nil
	}
	pkey, pval, rest, wellFormed := cutPathLeafErr(path)
	if !wellFormed {
		return Hash{}, nil, ErrInvalidPath
	}
	if !Key(pkey).HasPrefix(prefix) {
		// Looking up prefix as a key ended at a key not starting with prefix.
		// Since any key starting with prefix would have been reached instead,
		// no key in the tree starts with prefix, and the whole path proves it.
		return emptyTreeHash, path, nil
	}

	// Looking up prefix as a key ended inside the subtree of keys starting
	// with prefix. Walking up from that leaf, each node splitting at a bit
	// index at or past the end of the prefix is still inside the subtree;
	// the first node splitting at an earlier bit index is the subtree's parent.
	// So the hash computed just before that node is the subtree hash,
	// and the remaining steps are the proof.
	pbits := 8 * len(prefix)
	h := hashLeaf(pkey, pval)
	for len(rest) > 0 {
		b, sib, next, wellFormed := cutPathStepErr(rest)
		if !wellFormed {
			return Hash{}, nil, ErrInvalidPath
		}
		if b < pbits {
			break
		}
		if bit(pkey, b) == 0 {
			h = hashInner(b, h, sib)
		} else {
			h = hashInner(b, sib, h)
		}
		rest = next
	}
	return h, rest, nil
}

// cutPathStepErr cuts the leading (bit index, sibling hash) step from the
// path proof path, returning the step, the remaining path steps, and
// whether path began with a well-formed step.
func cutPathStepErr(path Proof) (b int, sib Hash, rest Proof, ok bool) {
	ub, n := binary.Uvarint(path)
	if n <= 0 || ub >= maxKeyBits || len(path)-n < 32 {
		return 0, Hash{}, nil, false
	}
	return int(ub), Hash(path[n : n+32]), path[n+32:], true
}

// VerifyLookup verifies a proof that a lookup for key in snap
// should return the result (val, ok).
// If the proof is not valid, VerifyLookup returns a non-nil error.
//
// [VerifyPresent] and [VerifyNotPresent] are convenience functions
// that wrap VerifyLookup.
func VerifyLookup(snap Snapshot, key, val []byte, ok bool, proof Proof) error {
	if !ok && len(val) != 0 {
		return ErrInvalidLookup
	}
	if !ok && len(proof) == 0 {
		if snap.Hash == emptyTreeHash {
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

	h, err := verifyPath(h, key, pkey, anyBit, proof)
	if err != nil {
		return err
	}
	if h != snap.Hash {
		return ErrInvalidProof
	}
	return nil
}

// anyBit is the maxBit to pass to [verifyPath] to impose no bound
// of its own. It is far above [maxKeyBits], the largest bit index
// any tree can produce.
const anyBit = 1 << 30

// verifyPath runs path verification on the (bit index, sibling hash) steps
// in proof, starting from the hash h computed for the end of the path and
// returning the hash computed for the start of the path (the tree root).
//
// The bit indexes must be strictly decreasing, starting below maxBit.
// The bits of key at those indexes decide whether each sibling hash is a
// left or right input, and they must match the bits of pkey, the key
// whose leaf the path actually ends at.
func verifyPath(h Hash, key, pkey []byte, maxBit int, proof Proof) (Hash, error) {
	b := maxBit
	for len(proof) > 0 {
		ub, n := binary.Uvarint(proof)
		if n <= 0 || ub >= uint64(b) {
			return Hash{}, ErrInvalidProof
		}
		b = int(ub)
		proof = proof[n:]
		if len(proof) < 32 {
			return Hash{}, ErrInvalidProof
		}
		var sib Hash
		sib, proof = Hash(proof[:32]), proof[32:]
		if bit(key, b) != bit(pkey, b) {
			return Hash{}, ErrInvalidProof
		}
		if bit(key, b) == 0 {
			h = hashInner(b, h, sib)
		} else {
			h = hashInner(b, sib, h)
		}
	}
	return h, nil
}

// VerifyPresent is shorthand for [VerifyLookup](snap, key[:], val[:], true, proof).
func VerifyPresent(snap Snapshot, key Key, val Val, proof Proof) error {
	return VerifyLookup(snap, key[:], val[:], true, proof)
}

// VerifyNotPresent is shorthand for [VerifyLookup](snap, key[:], nil, false, proof).
func VerifyNotPresent(snap Snapshot, key Key, proof Proof) error {
	return VerifyLookup(snap, key[:], nil, false, proof)
}

// VerifyPrefix verifies a proof that the subtree of key-value pairs
// with keys starting with prefix in snap has the given tree hash.
// If the proof is not valid, VerifyPrefix returns an error.
//
// A valid proof establishes that the subtree contains every key-value pair
// whose key starts with prefix. It does not establish that the subtree
// contains nothing else. See the “One-Sided Weakness of Prefix Proofs”
// section in the package documentation.
func VerifyPrefix(snap Snapshot, prefix []byte, hash Hash, proof Proof) error {
	if hash == emptyTreeHash {
		// Claim: no key in the tree starts with prefix.
		if len(proof) == 0 {
			// Only an empty tree can make that claim without a proof.
			if snap.Hash == emptyTreeHash {
				return nil
			}
			return ErrInvalidProof
		}
		// The proof is the path proof for looking up prefix as a key.
		// It must end at a key that does not start with prefix,
		// which proves no such key is in the tree.
		altkey, altval, rest, ok := cutPathLeafErr(proof)
		if !ok {
			return ErrInvalidProof
		}
		if Key(altkey).HasPrefix(prefix) {
			return ErrInvalidProof
		}
		h, err := verifyPath(hashLeaf(altkey, altval), prefix, altkey, anyBit, rest)
		if err != nil {
			return err
		}
		if h != snap.Hash {
			return ErrInvalidProof
		}
		return nil
	}

	// Claim: the subtree with the given hash contains every key starting with prefix.
	// Path verification resumes at the subtree, so every remaining step must split
	// at a bit index inside the prefix; otherwise the claimed subtree could be
	// more specific than the prefix and omit some keys starting with prefix.
	h, err := verifyPath(hash, prefix, prefix, 8*len(prefix), proof)
	if err != nil {
		return err
	}
	if h != snap.Hash {
		return ErrInvalidProof
	}
	return nil
}

// cutPathLeafErr cuts the leading key-value pair from the path proof
// path, returning the pair, the remaining path steps, and whether path
// began with a well-formed key-value pair.
func cutPathLeafErr(path Proof) (key Key, val Val, rest Proof, ok bool) {
	key, rest, ok = cutVar(path)
	if !ok {
		return nil, nil, nil, false
	}
	val, rest, ok = cutVar(rest)
	if !ok {
		return nil, nil, nil, false
	}
	return key, val, rest, true
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
		return emptyTreeHash
	}
	for len(s) >= 2 {
		s = append(s[:len(s)-2], s[len(s)-2].merge(s[len(s)-1]))
	}
	return s[0].hash
}
