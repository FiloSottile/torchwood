// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mpt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"iter"
)

// hash returns the hash for the tree position p, which must be clean:
// an inner node's ihash must already be up to date (see [diskTree.rehash]).
func (t *diskTree) hash(p ptr) (Hash, error) {
	if p.isLeaf() {
		key, val, err := t.leafKeyVal(p.addr())
		if err != nil {
			return Hash{}, err
		}
		return hashLeaf(key, val), nil
	}
	n, err := t.node(p.addr())
	if err != nil {
		return Hash{}, err
	}
	return n.ihash(), nil
}

var lazyHash = false

// unhash marks n's hash invalid or recomputes it,
// depending on the [lazyHash] setting.
func (n *diskNode) unhash(t *diskTree) error {
	if !lazyHash {
		_, err := t.rehash(nodePtr(t.addr(n)), true)
		return err
	}
	if n.dirty() {
		return nil
	}
	return n.setDirty(t, true)
}

// rehash updates and returns the hash for the tree position p,
// recomputing (and, for a node, persisting) it if dirty or force is set.
func (t *diskTree) rehash(p ptr, force bool) (Hash, error) {
	if p.isLeaf() {
		return t.hash(p)
	}
	n, err := t.node(p.addr())
	if err != nil {
		return Hash{}, err
	}
	if n.dirty() || force {
		lhash, err := t.rehash(n.left(), false)
		if err != nil {
			return Hash{}, err
		}
		rhash, err := t.rehash(n.right(), false)
		if err != nil {
			return Hash{}, err
		}
		if err := n.setIHash(t, hashInner(n.bit(), lhash, rhash)); err != nil {
			return Hash{}, err
		}
		if err := n.setDirty(t, false); err != nil {
			return Hash{}, err
		}
	}
	return n.ihash(), nil
}

// Snap returns a snapshot of t.
func (t *diskTree) Snap(version int64) (Snapshot, error) {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	if err := t.snap(version); err != nil {
		return Snapshot{}, err
	}
	_ = t.check // t.check()
	return Snapshot{t.hdr().version(), t.hdr().hash()}, nil
}

func (t *diskTree) snap(version int64) error {
	if t.err != nil {
		return t.err
	}
	if t.hdr().dirty() {
		// Note: Not using a mutation group because we might be
		// updating arbitrarily many hashes during rehash.
		// Without group, ordering matters: write hash before dirty
		// and both before version.
		//
		// Also note: dirty implies that tree is non-empty, so the root is not nil.
		hash, err := t.rehash(t.hdr().root(), false)
		if err != nil {
			return err
		}
		if err := t.hdr().setHash(t, hash); err != nil {
			return err
		}
		if err := t.hdr().setDirty(t, false); err != nil {
			return err
		}
	}
	if version >= 0 {
		if err := t.hdr().setVersion(t, version); err != nil {
			return err
		}
	}
	return nil
}

// Version returns version information about the tree.
func (t *diskTree) Version() (version int64, exact bool) {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	hdr := t.hdr()
	return hdr.version(), hdr.exact()
}

// Set sets the value associated with key to val.
func (t *diskTree) Set(key Key, val Val) error {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	if t.err != nil {
		return t.err
	}

	if t.hdr().exact() {
		// Clear exact and flush to disk (in the memory files)
		// before we make any writes to the disk leaf file,
		// so that we know the disk leaf file may be ahead of the memory file.
		if err := t.hdr().setExact(t, false); err != nil {
			return err
		}
		if err := t.pmem.Sync(); err != nil {
			return err
		}
	}

	// Keep all writes for this Set in the same group.
	// We write one node and the dirty field for log N nodes,
	// so it fits easily in the mutation group limit.
	t.pmem.BeginGroup()
	defer t.pmem.EndGroup()

	if !t.hdr().dirty() {
		if err := t.hdr().setDirty(t, true); err != nil {
			return err
		}
	}
	b, err := t.setChild(hdrRoot, -1, key, val)
	if err != nil {
		return err
	}
	if b >= 0 {
		// setChild always resolves at or before the root's context
		// bit of -1, since every real divergence bit is >= 0.
		panic("bad add")
	}

	// Also unhash the (possibly new) root, in case setChild's recursive
	// unhash calls never reached it: that happens when Set just created
	// it, or when it's a single leaf. This keeps every Set fully
	// rehashing the tree in the default eager mode, so the tree's
	// on-disk bytes depend only on its current contents, not on the
	// history of Sets that produced them.
	if root := t.hdr().root(); !root.isLeaf() {
		n, err := t.node(root.addr())
		if err != nil {
			return err
		}
		if err := n.unhash(t); err != nil {
			return err
		}
	}
	_ = t.check // t.check()
	return nil
}

// setChild sets key to val within the subtree addressed by the tagged
// pointer field at fieldAddr (either hdrRoot or a node's left or right
// field). nbit is the bit position of whatever split routed the caller
// to this field (-1 for the root field): every key already in the
// subtree is known to agree with key on bit nbit, if nbit >= 0,
// because that decided the route, but not necessarily on any bit
// between nbit and the subtree's own next split, if any.
//
// If key turns out to diverge from the whole subtree at some bit
// b <= nbit — discovered by comparing against a leaf reached by
// recursing further in, and only possible to learn that late — the
// divergence in fact belongs at or above fieldAddr, not inside it, so
// setChild leaves fieldAddr untouched and returns b for an ancestor
// with a shallower context to insert the split instead. It returns a
// negative b once the update, including any such split, has been
// fully applied, which may include rewriting fieldAddr itself.
func (t *diskTree) setChild(fieldAddr addr, nbit int, key Key, val Val) (b int, err error) {
	p := ptr(t.addrAt(fieldAddr))

	if p.isNil() {
		// Empty subtree, only possible for the root of an empty tree:
		// the new key becomes the entire tree, as a single leaf.
		lp, err := t.newLeaf(key, val)
		if err != nil {
			return 0, err
		}
		return -1, t.setAddrAt(fieldAddr, addr(lp))
	}

	if p.isLeaf() {
		ekey, err := t.leafKey(p.addr())
		if err != nil {
			return 0, err
		}
		b := ekey.overlap(key)
		if b == maxKeyBits {
			// Same key: update the value in place, which may relocate it.
			newAddr, err := t.setLeafVal(p.addr(), val)
			if err != nil {
				return 0, err
			}
			if newAddr != p.addr() {
				return -1, t.setAddrAt(fieldAddr, addr(leafPtr(newAddr)))
			}
			return -1, nil
		}
		if b <= nbit {
			// The divergence belongs at or above our own context.
			return b, nil
		}
		return -1, t.split(fieldAddr, key, val, b, p)
	}

	// p is a node: recurse into whichever child agrees with key so far.
	n, err := t.node(p.addr())
	if err != nil {
		return 0, err
	}
	nbit2 := n.bit()
	childField := t.addr(n) + nodeLeft
	if key.bit(nbit2) != 0 {
		childField = t.addr(n) + nodeRight
	}
	cb, err := t.setChild(childField, nbit2, key, val)
	if err != nil {
		return 0, err
	}
	if cb < 0 {
		return -1, n.unhash(t)
	}
	if cb <= nbit {
		return cb, nil
	}
	// cb belongs strictly between nbit and nbit2: split here,
	// replacing this whole subtree (p, unchanged) with the new split.
	return -1, t.split(fieldAddr, key, val, cb, p)
}

// split rewrites the tagged pointer field at fieldAddr, currently p, to
// a new node splitting at bit b between p and a new leaf for key, val.
func (t *diskTree) split(fieldAddr addr, key Key, val Val, b int, p ptr) error {
	np, err := t.newLeaf(key, val)
	if err != nil {
		return err
	}
	left, right := np, p
	if key.bit(b) != 0 {
		left, right = p, np
	}
	n, err := t.newSplit(b, left, right)
	if err != nil {
		return err
	}
	return t.setAddrAt(fieldAddr, addr(nodePtr(t.addr(n))))
}

// Predict returns the hash of the tree that would result from
// applying the given changes (sorted by key) to the tree,
// without modifying the tree.
func (t *diskTree) Predict(changes []KeyVal) (Hash, error) {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	if t.err != nil {
		return Hash{}, t.err
	}
	if t.hdr().dirty() {
		return Hash{}, ErrModifiedTree
	}

	if err := checkChanges(changes); err != nil {
		return Hash{}, err
	}
	s, list, err := t.predict([]node{}, t.hdr().root(), changes)
	if err != nil {
		return Hash{}, err
	}
	for _, kv := range list {
		s = reduce(append(s, node{prefix(kv.Key, maxKeyBits), hashLeaf(kv.Key, kv.Val)}))
	}
	return hashStack(s), nil
}

// leftmostKey returns the key of the leftmost leaf in the subtree at p,
// which is not nil. It is a representative key for the whole subtree:
// every key there agrees with it on the bits leading to p.
func (t *diskTree) leftmostKey(p ptr) (Key, error) {
	for !p.isLeaf() {
		n, err := t.node(p.addr())
		if err != nil {
			return nil, err
		}
		p = n.left()
	}
	return t.leafKey(p.addr())
}

// predict calculates the edited tree hash for the subtree at p.
func (t *diskTree) predict(s []node, p ptr, list []KeyVal) ([]node, []KeyVal, error) {
	if p.isNil() {
		return s, list, nil
	}

	if p.isLeaf() {
		key, val, err := t.leafKeyVal(p.addr())
		if err != nil {
			return nil, nil, err
		}
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
		return s, list, nil
	}

	n, err := t.node(p.addr())
	if err != nil {
		return nil, nil, err
	}
	nbit := n.bit()
	key, err := t.leftmostKey(p)
	if err != nil {
		return nil, nil, err
	}
	pkey := prefix(key, nbit)

	// Stack modifications before node.
	for len(list) > 0 && prefix(list[0].Key, nbit).compare(pkey) < 0 {
		k, v := list[0].Key, list[0].Val
		list = list[1:]
		s = reduce(append(s, node{prefix(k, maxKeyBits), hashLeaf(k, v)}))
	}

	// Stack entire subtree, if no modifications inside it.
	if len(list) == 0 || pkey.compare(prefix(list[0].Key, nbit)) < 0 {
		s = reduce(append(s, node{pkey, n.ihash()}))
		return s, list, nil
	}

	// Otherwise, apply modifications within subtree.
	s, list, err = t.predict(s, n.left(), list)
	if err != nil {
		return nil, nil, err
	}
	s, list, err = t.predict(s, n.right(), list)
	if err != nil {
		return nil, nil, err
	}
	return s, list, nil
}

// Path returns the path proof for key in t.
func (t *diskTree) Path(key Key) (Proof, error) {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	if t.err != nil {
		return nil, t.err
	}
	if t.hdr().dirty() {
		return nil, ErrModifiedTree
	}
	return t.path(t.hdr().root(), key)
}

// path returns the path proof for key in the subtree at p.
func (t *diskTree) path(p ptr, key Key) (Proof, error) {
	if p.isNil() {
		return Proof{}, nil
	}

	if p.isLeaf() {
		nkey, nval, err := t.leafKeyVal(p.addr())
		if err != nil {
			return nil, err
		}
		var proof Proof
		proof = binary.AppendUvarint(proof, uint64(len(nkey)))
		proof = append(proof, nkey...)
		proof = binary.AppendUvarint(proof, uint64(len(nval)))
		proof = append(proof, nval...)
		return proof, nil
	}

	n, err := t.node(p.addr())
	if err != nil {
		return nil, err
	}
	nbit := n.bit()
	child, sib := n.left(), n.right()
	if key.bit(nbit) == 1 {
		child, sib = sib, child
	}
	sibHash, err := t.hash(sib)
	if err != nil {
		return nil, err
	}

	proof, err := t.path(child, key)
	if err != nil {
		return nil, err
	}
	proof = binary.AppendUvarint(proof, uint64(nbit))
	proof = append(proof, sibHash[:]...)
	return proof, nil
}

// Scan returns an iterator over key-val pairs whose keys start with prefix.
func (t *diskTree) Scan(prefix []byte) iter.Seq2[KeyVal, error] {
	return func(yield func(KeyVal, error) bool) {
		t.mmu.RLock()
		defer t.mmu.RUnlock()

		if t.err != nil {
			yield(KeyVal{}, t.err)
			return
		}
		p, err := t.subtree(prefix)
		if err != nil {
			yield(KeyVal{}, err)
			return
		}
		if p.isNil() {
			return
		}
		t.scan(p, yield)
	}
}

// subtree returns the tree position holding every key that starts with
// prefix, or the nil ptr if the tree holds no such key.
func (t *diskTree) subtree(prefix []byte) (ptr, error) {
	p := t.hdr().root()
	if p.isNil() {
		return 0, nil
	}

	// Look up prefix as if it were a key, stopping at the first leaf,
	// or at the first node that splits at a bit index at or past the
	// end of the prefix: every key below that point agrees with the
	// others there, so either all of them start with prefix or none do.
	pbits := 8 * len(prefix)
	for !p.isLeaf() {
		n, err := t.node(p.addr())
		if err != nil {
			return 0, err
		}
		if n.bit() >= pbits {
			break
		}
		p = n.left()
		if bit(prefix, n.bit()) != 0 {
			p = n.right()
		}
	}

	// Check one key to decide for all of them.
	key, err := t.leftmostKey(p)
	if err != nil {
		return 0, err
	}
	if !key.HasPrefix(prefix) {
		return 0, nil
	}
	return p, nil
}

// scan yields the key-val pairs in the subtree at p, in key order,
// reporting whether iteration should continue.
func (t *diskTree) scan(p ptr, yield func(KeyVal, error) bool) bool {
	if p.isLeaf() {
		key, val, err := t.leafKeyVal(p.addr())
		if err != nil {
			yield(KeyVal{}, err)
			return false
		}
		return yield(KeyVal{key, val}, nil)
	}

	n, err := t.node(p.addr())
	if err != nil {
		yield(KeyVal{}, err)
		return false
	}
	return t.scan(n.left(), yield) && t.scan(n.right(), yield)
}

func (t *diskTree) check() {
	println("check")
	h, err := t.checkTree(t.hdr().root(), 1)
	if err != nil {
		panic(err)
	}
	if h != t.hdr().hash() && !t.hdr().dirty() {
		fmt.Printf("have %v want %v\n", t.hdr().hash(), h)
		panic("bad hash")
	}
	println("check OK")
}

// checkTree recomputes the hash of the subtree at p, printing every node
// and leaf it visits, and panics if any node's cached ihash is wrong.
func (t *diskTree) checkTree(p ptr, depth int) (Hash, error) {
	if p.isNil() {
		return emptyTreeHash, nil
	}
	if p.isLeaf() {
		key, val, err := t.leafKeyVal(p.addr())
		if err != nil {
			return Hash{}, err
		}
		fmt.Printf("%*sleaf %#x %v %v %v\n", depth*2, "", p.addr(), key, val, hashLeaf(key, val))
		return hashLeaf(key, val), nil
	}
	n, err := t.node(p.addr())
	if err != nil {
		return Hash{}, err
	}
	fmt.Printf("%*s%d %#x %#x %#x %v dirty=%v\n", depth*2, "", n.bit(), t.addr(n), n.left(), n.right(), n.ihash(), n.dirty())

	left, err := t.checkTree(n.left(), depth+1)
	if err != nil {
		return Hash{}, err
	}
	right, err := t.checkTree(n.right(), depth+1)
	if err != nil {
		return Hash{}, err
	}
	h := hashInner(n.bit(), left, right)
	if h != n.ihash() && !n.dirty() {
		fmt.Printf("%*shave %v want %v\n", depth*2, "", n.ihash(), h)
		panic("bad hash")
	}
	return h, nil
}
