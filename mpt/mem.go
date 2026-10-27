// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mpt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
)

// A memTree is an in-memory [Tree].
type memTree struct {
	version int64  // version number of tree
	exact   bool   // version is exact
	root    memAny // tree root: nil, *memNode, or *memLeaf
	hash    Hash   // overall tree hash
	dirty   bool   // Set called without Snap
	err     error  // sticky error condition
}

// A memAny is a tree position: a *memNode or a *memLeaf.
type memAny interface {
	// key and val return a representative key-value pair for the
	// position: the position's own key and val if it is a *memLeaf,
	// or otherwise the key and val of the leftmost leaf beneath it,
	// which every other key beneath it agrees with on the bits
	// leading down to the position.
	key() Key
	val() Val

	// rehash returns the position's hash, recomputing and caching it
	// first if it is a dirty *memNode.
	rehash() Hash
}

// A memNode is a single inner node in the in-memory tree.
//
// Unlike in a standard Patricia tree implementation, a memNode is
// never also one of its own two children: every leaf is referenced
// directly, as a *memLeaf, by its parent's left or right field (or,
// for a one-leaf tree, by the memTree's own root field), so a memNode
// never needs to store leaf data of its own.
type memNode struct {
	bit   int  // bit position deciding between left and right
	dirty bool // needs rehashing
	ihash Hash
	left  memAny
	right memAny
}

// A memLeaf is a single leaf in the in-memory tree.
type memLeaf struct {
	k Key
	v Val
}

func (l *memLeaf) key() Key     { return l.k }
func (l *memLeaf) val() Val     { return l.v }
func (l *memLeaf) rehash() Hash { return hashLeaf(l.k, l.v) }

func (n *memNode) key() Key { return n.left.key() }
func (n *memNode) val() Val { return n.left.val() }

// rehash updates n.ihash if needed and then returns it.
func (n *memNode) rehash() Hash {
	if n.dirty {
		n.ihash = hashInner(n.bit, n.left.rehash(), n.right.rehash())
		n.dirty = false
	}
	return n.ihash
}

// unhash marks n's hash invalid.
func (n *memNode) unhash() {
	n.dirty = true
}

// NewMemTree returns a new in-memory [Tree].
func NewMemTree() Tree {
	t := &memTree{
		hash:  emptyTreeHash,
		exact: true,
	}
	return t
}

// Sync is a no-op since the data is only in memory.
func (t *memTree) Sync() error {
	return nil
}

// Close is a no-op since the data is only in memory.
func (t *memTree) Close() error {
	if t.err != nil {
		return t.err
	}
	t.err = errors.New("tree is closed")
	return nil
}

func (t *memTree) UnsafeUnmap() error { return nil }

// Stat returns the tree metadata.
func (t *memTree) Version() (version int64, exact bool) {
	return t.version, t.exact
}

// Snap returns a snapshot of t.
func (t *memTree) Snap(version int64) (Snapshot, error) {
	if t.err != nil {
		return Snapshot{}, t.err
	}
	if t.dirty {
		// nothing, but keep the read for causing races with Set
	}
	t.dirty = false
	if version >= 0 {
		t.version = version
	}
	if t.root != nil {
		t.hash = t.root.rehash()
		_ = t.check // t.check()
	}
	t.exact = true
	return Snapshot{t.version, t.hash}, nil
}

// Set sets the value associated with key to val.
func (t *memTree) Set(key Key, val Val) error {
	if t.err != nil {
		return t.err
	}
	t.dirty = true
	t.exact = false
	if setChild(-1, &t.root, key, val) >= 0 {
		panic("bad add")
	}
	_ = t.check // t.check()
	return nil
}

// setChild sets key to val within the subtree at *pos (nil, *memNode,
// or *memLeaf). nbit is the bit position of whatever split routed the
// caller to pos (-1 for the root): every key already in the subtree
// is known to agree with key on bit nbit, if nbit >= 0, because that
// decided the route, but not necessarily on any bit between nbit and
// the subtree's own next split, if any.
//
// If key turns out to diverge from the whole subtree at some bit
// b <= nbit — discovered by comparing against a leaf reached by
// recursing further in, and only possible to learn that late — the
// divergence in fact belongs at or above pos, not inside it, so
// setChild leaves *pos untouched and returns b for an ancestor with a
// shallower context to insert the split instead. It returns a
// negative b once the update, including any such split, has been
// fully applied, which may include rewriting *pos itself.
func setChild(nbit int, pos *memAny, key Key, val Val) int {
	switch p := (*pos).(type) {
	case nil:
		// Empty subtree, only possible for the root of an empty tree:
		// the new key becomes the entire tree, as a single leaf.
		*pos = &memLeaf{k: key, v: val}
		return -1

	case *memLeaf:
		b := p.k.overlap(key)
		if b == maxKeyBits {
			// Same key: update the value in place.
			p.v = val
			return -1
		}
		if b <= nbit {
			// The divergence belongs at or above our own context.
			return b
		}
		// Different key, diverging strictly after nbit: split here,
		// between the new key and the existing leaf.
		*pos = split(b, key, val, p)
		return -1

	case *memNode:
		// p is a node: recurse into whichever child agrees with key so far.
		child := &p.left
		if key.bit(p.bit) != 0 {
			child = &p.right
		}
		cb := setChild(p.bit, child, key, val)
		if cb < 0 {
			p.unhash()
			return -1
		}
		if cb <= nbit {
			return cb
		}
		// cb belongs strictly between nbit and p.bit: split here,
		// replacing this whole subtree (p, unchanged) with the new split.
		*pos = split(cb, key, val, p)
		return -1
	}
	panic("mpt: invalid tree position")
}

// split returns a new node splitting at bit b between the existing
// subtree p (a *memNode or *memLeaf) and a new leaf for key, val.
func split(b int, key Key, val Val, p memAny) *memNode {
	leaf := &memLeaf{k: key, v: val}
	left, right := memAny(leaf), p
	if key.bit(b) != 0 {
		left, right = p, leaf
	}
	return &memNode{bit: b, dirty: true, left: left, right: right}
}

// Predict returns the hash of the tree that would result from
// applying the given changes (sorted by key) to the tree,
// without modifying the tree.
func (t *memTree) Predict(changes []KeyVal) (Hash, error) {
	if t.err != nil {
		return Hash{}, t.err
	}
	if t.dirty {
		return Hash{}, ErrModifiedTree
	}

	if err := checkChanges(changes); err != nil {
		return Hash{}, err
	}
	s, list := predict([]node{}, t.root, changes)
	for _, kv := range list {
		s = reduce(append(s, node{prefix(kv.Key, maxKeyBits), hashLeaf(kv.Key, kv.Val)}))
	}
	return hashStack(s), nil
}

// predict calculates the edited tree hash for the subtree at pos.
func predict(s []node, pos memAny, list []KeyVal) ([]node, []KeyVal) {
	switch p := pos.(type) {
	case nil:
		return s, list

	case *memLeaf:
		key, val := p.key(), p.val()
		pkey := prefix(key, maxKeyBits)

		// Stack modifications before leaf.
		for len(list) > 0 && prefix(list[0].Key, maxKeyBits).compare(pkey) < 0 {
			k, v := list[0].Key, list[0].Val
			list = list[1:]
			s = reduce(append(s, node{prefix(k, maxKeyBits), hashLeaf(k, v)}))
		}

		// Stack leaf, possibly replaced.
		if len(list) > 0 && bytes.Equal(list[0].Key, key) {
			val = list[0].Val
			list = list[1:]
		}
		s = reduce(append(s, node{pkey, hashLeaf(key, val)}))
		return s, list

	case *memNode:
		nbit := p.bit
		pkey := prefix(p.key(), nbit)

		// Stack modifications before node.
		for len(list) > 0 && prefix(list[0].Key, nbit).compare(pkey) < 0 {
			k, v := list[0].Key, list[0].Val
			list = list[1:]
			s = reduce(append(s, node{prefix(k, maxKeyBits), hashLeaf(k, v)}))
		}

		// Stack entire subtree, if no modifications inside it.
		if len(list) == 0 || pkey.compare(prefix(list[0].Key, nbit)) < 0 {
			s = reduce(append(s, node{pkey, p.rehash()}))
			return s, list
		}

		// Otherwise, apply modifications within subtree.
		s, list = predict(s, p.left, list)
		s, list = predict(s, p.right, list)
		return s, list
	}
	panic("mpt: invalid tree position")
}

// Path returns the path proof for key in t.
func (t *memTree) Path(key Key) (Proof, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.dirty {
		return nil, ErrModifiedTree
	}
	return path(t.root, key), nil
}

// path returns the path proof for key in the subtree at pos.
func path(pos memAny, key Key) Proof {
	switch p := pos.(type) {
	case nil:
		return Proof{}

	case *memLeaf:
		var proof Proof
		proof = binary.AppendUvarint(proof, uint64(len(p.k)))
		proof = append(proof, p.k...)
		proof = binary.AppendUvarint(proof, uint64(len(p.v)))
		proof = append(proof, p.v...)
		return proof

	case *memNode:
		child, sib := p.left, p.right
		if key.bit(p.bit) == 1 {
			child, sib = sib, child
		}
		sibHash := sib.rehash()

		proof := path(child, key)
		proof = binary.AppendUvarint(proof, uint64(p.bit))
		proof = append(proof, sibHash[:]...)
		return proof
	}
	panic("mpt: invalid tree position")
}

// Scan returns an iterator over key-val pairs whose keys start with prefix.
func (t *memTree) Scan(prefix []byte) iter.Seq2[KeyVal, error] {
	return func(yield func(KeyVal, error) bool) {
		if t.err != nil {
			yield(KeyVal{}, t.err)
			return
		}
		pos := subtree(t.root, prefix)
		if pos == nil {
			return
		}
		scan(pos, yield)
	}
}

// subtree returns the tree position holding every key that starts
// with prefix, or nil if the tree holds no such key.
func subtree(pos memAny, prefix []byte) memAny {
	if pos == nil {
		return nil
	}

	// Look up prefix as if it were a key, stopping at the first leaf,
	// or at the first node that splits at a bit index at or past the
	// end of the prefix: every key below that point agrees with the
	// others there, so either all of them start with prefix or none do.
	pbits := 8 * len(prefix)
	for {
		n, ok := pos.(*memNode)
		if !ok || n.bit >= pbits {
			break
		}
		pos = n.left
		if bit(prefix, n.bit) != 0 {
			pos = n.right
		}
	}

	// Check one key to decide for all of them.
	if !pos.key().HasPrefix(prefix) {
		return nil
	}
	return pos
}

// scan yields the key-val pairs in the subtree at pos, in key order,
// reporting whether iteration should continue.
func scan(pos memAny, yield func(KeyVal, error) bool) bool {
	switch p := pos.(type) {
	case *memLeaf:
		return yield(KeyVal{p.k, p.v}, nil)
	case *memNode:
		return scan(p.left, yield) && scan(p.right, yield)
	}
	panic("mpt: invalid tree position")
}

// check checks all the tree invariants, walking the entire tree.
// It is too slow for real use but helpful to insert when debugging.
func (t *memTree) check() {
	println("check")
	h := checkPos(t.root, 1)
	if h != t.hash && (t.root == nil || !t.dirty) {
		fmt.Printf("have %v want %v\n", t.hash, h)
		panic("bad hash")
	}
}

func checkPos(pos memAny, depth int) Hash {
	switch p := pos.(type) {
	case nil:
		return emptyTreeHash

	case *memLeaf:
		fmt.Printf("%*sleaf %v %v %p %v\n", depth*2, "", p.k, p.v, p, hashLeaf(p.k, p.v))
		return hashLeaf(p.k, p.v)

	case *memNode:
		fmt.Printf("%*s%d %p %p %p %v\n", depth*2, "", p.bit, p, p.left, p.right, p.ihash)
		h := hashInner(p.bit, checkPos(p.left, depth+1), checkPos(p.right, depth+1))
		if h != p.ihash && !p.dirty {
			fmt.Printf("%*shave %v want %v\n", depth*2, "", p.ihash, h)
			panic("bad hash")
		}
		return h
	}
	panic("mpt: invalid tree position")
}
