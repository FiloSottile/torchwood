// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package torchwood implements a tlog client and various c2sp.org/signed-note,
// c2sp.org/tlog-cosignature, c2sp.org/tlog-checkpoint, and c2sp.org/tlog-tiles
// functions, including extensions to the [golang.org/x/mod/sumdb/tlog] and
// [golang.org/x/mod/sumdb/note] packages.
package torchwood

import (
	"errors"
	"fmt"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"
)

// RightEdge returns the stored hash indexes of the right edge of a tree of
// size n. These are the same hashes that are combined into a [tlog.TreeHash]
// and allow producing record and tree proofs for any size bigger than n. See
// [tlog.StoredHashIndex] for the definition of stored hash indexes.
//
// n must not be greater than 2^62, the largest supported tree size; RightEdge
// panics otherwise.
func RightEdge(n int64) []int64 {
	if n > maxN {
		panic("tlog: tree size out of range in RightEdge")
	}
	var lo int64
	var idx []int64
	for lo < n {
		k, level := maxpow2(n - lo + 1)
		idx = append(idx, tlog.StoredHashIndex(level, lo>>level))
		lo += k
	}
	return idx
}

// A HashProof is a verifiable proof that a particular tree head contains a
// particular subtree hash. A [tlog.RecordProof] is a special case of a
// HashProof where the subtree has size 1. A HashProof is a special case of a
// [SubtreeProof] where the subtree is full (i.e. the size is a power of two).
type HashProof []tlog.Hash

// ProveHash returns the proof that the tree of size t contains the hash with
// [tlog.StoredHashIndex] i.
func ProveHash(t, i int64, r tlog.HashReader) (HashProof, error) {
	if t < 0 || i < 0 || i >= tlog.StoredHashIndex(0, t) {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveHash")
	}
	// The hash with stored index i is the hash of the full subtree [n<<level,
	// (n+1)<<level), so a HashProof is a SubtreeProof for that subtree.
	level, n := tlog.SplitStoredHashIndex(i)
	p, err := ProveSubtree(t, n<<level, (n+1)<<level, r)
	if err != nil {
		return nil, err
	}
	return HashProof(p), nil
}

var errProofFailed = errors.New("invalid transparency proof")

// CheckHash verifies that p is a valid proof that the tree of size t
// with hash th has an i'th hash with hash h.
func CheckHash(p HashProof, t int64, th tlog.Hash, i int64, h tlog.Hash) error {
	if t < 0 || i < 0 || i >= tlog.StoredHashIndex(0, t) {
		return fmt.Errorf("tlog: invalid inputs in CheckHash")
	}
	level, n := tlog.SplitStoredHashIndex(i)
	return CheckSubtree(SubtreeProof(p), t, th, n<<level, (n+1)<<level, h)
}

// The functions below are unmodified copies from package tlog.

// subTreeIndex returns the storage indexes needed to compute
// the hash for the subtree containing records [lo, hi),
// appending them to need and returning the result.
// See https://tools.ietf.org/html/rfc6962#section-2.1
func subTreeIndex(lo, hi int64, need []int64) []int64 {
	// See subTreeHash below for commentary.
	for lo < hi {
		k, level := maxpow2(hi - lo + 1)
		if lo&(k-1) != 0 {
			panic("tlog: bad math in subTreeIndex")
		}
		need = append(need, tlog.StoredHashIndex(level, lo>>uint(level)))
		lo += k
	}
	return need
}

// subTreeHash computes the hash for the subtree containing records [lo, hi),
// assuming that hashes are the hashes corresponding to the indexes
// returned by subTreeIndex(lo, hi).
// It returns any leftover hashes.
func subTreeHash(lo, hi int64, hashes []tlog.Hash) (tlog.Hash, []tlog.Hash) {
	// Repeatedly partition the tree into a left side with 2^level nodes,
	// for as large a level as possible, and a right side with the fringe.
	// The left hash is stored directly and can be read from storage.
	// The right side needs further computation.
	numTree := 0
	for lo < hi {
		k, _ := maxpow2(hi - lo + 1)
		if lo&(k-1) != 0 || lo >= hi {
			panic("tlog: bad math in subTreeHash")
		}
		numTree++
		lo += k
	}

	if len(hashes) < numTree {
		panic("tlog: bad index math in subTreeHash")
	}

	// Reconstruct hash.
	h := hashes[numTree-1]
	for i := numTree - 2; i >= 0; i-- {
		h = tlog.NodeHash(hashes[i], h)
	}
	return h, hashes[numTree:]
}

// maxpow2 returns k, the largest power of two smaller than n, as well as
// l = log₂ k (so k = 1<<l), for n >= 2.
func maxpow2(n int64) (k int64, l int) {
	l = bits.Len64(uint64(n-1)) - 1
	return 1 << l, l
}

// leafProofIndex builds the list of indexes needed to construct the proof
// that leaf n is contained in the subtree with leaves [lo, hi).
// It appends those indexes to need and returns the result.
// See https://tools.ietf.org/html/rfc6962#section-2.1.1
func leafProofIndex(lo, hi, n int64, need []int64) []int64 {
	// See leafProof below for commentary.
	if !(lo <= n && n < hi) {
		panic("tlog: bad math in leafProofIndex")
	}
	if lo+1 == hi {
		return need
	}
	if k, _ := maxpow2(hi - lo); n < lo+k {
		need = leafProofIndex(lo, lo+k, n, need)
		need = subTreeIndex(lo+k, hi, need)
	} else {
		need = subTreeIndex(lo, lo+k, need)
		need = leafProofIndex(lo+k, hi, n, need)
	}
	return need
}

// leafProof constructs the proof that leaf n is contained in the subtree with leaves [lo, hi).
// It returns any leftover hashes as well.
// See https://tools.ietf.org/html/rfc6962#section-2.1.1
func leafProof(lo, hi, n int64, hashes []tlog.Hash) (RecordInSubtreeProof, []tlog.Hash) {
	// We must have lo <= n < hi or else the code here has a bug.
	if !(lo <= n && n < hi) {
		panic("tlog: bad math in leafProof")
	}

	if lo+1 == hi { // n == lo
		// Reached the leaf node.
		// The verifier knows what the leaf hash is, so we don't need to send it.
		return RecordInSubtreeProof{}, hashes
	}

	// Walk down the tree toward n.
	// Record the hash of the path not taken (needed for verifying the proof).
	var p RecordInSubtreeProof
	var th tlog.Hash
	if k, _ := maxpow2(hi - lo); n < lo+k {
		// n is on left side
		p, hashes = leafProof(lo, lo+k, n, hashes)
		th, hashes = subTreeHash(lo+k, hi, hashes)
	} else {
		// n is on right side
		th, hashes = subTreeHash(lo, lo+k, hashes)
		p, hashes = leafProof(lo+k, hi, n, hashes)
	}
	return append(p, th), hashes
}

// runRecordProof runs the proof p that leaf n is contained in the subtree with leaves [lo, hi).
// Running the proof means constructing and returning the implied hash of that
// subtree.
func runRecordProof(p RecordInSubtreeProof, lo, hi, n int64, leafHash tlog.Hash) (tlog.Hash, error) {
	// We must have lo <= n < hi or else the code here has a bug.
	if !(lo <= n && n < hi) {
		panic("tlog: bad math in runRecordProof")
	}

	if lo+1 == hi { // m == lo
		// Reached the leaf node.
		// The proof must not have any unnecessary hashes.
		if len(p) != 0 {
			return tlog.Hash{}, errProofFailed
		}
		return leafHash, nil
	}

	if len(p) == 0 {
		return tlog.Hash{}, errProofFailed
	}

	k, _ := maxpow2(hi - lo)
	if n < lo+k {
		th, err := runRecordProof(p[:len(p)-1], lo, lo+k, n, leafHash)
		if err != nil {
			return tlog.Hash{}, err
		}
		return tlog.NodeHash(th, p[len(p)-1]), nil
	} else {
		th, err := runRecordProof(p[:len(p)-1], lo+k, hi, n, leafHash)
		if err != nil {
			return tlog.Hash{}, err
		}
		return tlog.NodeHash(p[len(p)-1], th), nil
	}
}
