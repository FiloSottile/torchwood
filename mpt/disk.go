// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mpt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sync"

	"filippo.io/torchwood/mpt/internal/pmem"
)

// Tree Format
//
// The tree memory starts with a header:
//
//	version [8]
//	dirty   [1]
//	pad     [1]
//	root    [6]
//	hash   [32]
//	nodes   [8]
//
// The header is followed by a sequence of Patricia nodes of the form:
//
//	bitDirty [2]
//	left     [6]
//	right    [6]
//	ihash   [32]
//
// The "bitDirty" field is bit<<1 | dirty.
//
// The root, left, and right fields are disk offsets.
// Zero is a nil pointer (only possible for root),
// even offsets are byte offsets from tree memory,
// identifying another node, and odd offsets are
// (after subtracting 1) byte offsets in the leaf file.

const (
	// header offsets
	hdrVersion = 0
	hdrDirty   = 8
	hdrExact   = 9
	hdrRoot    = 10
	hdrHash    = 16
	hdrSize    = 48

	// node offsets
	nodeBitDirty = 0
	nodeLeft     = 2
	nodeRight    = 8
	nodeIHash    = 14
	nodeSize     = 46

	// address size
	addrSize = 6
)

// File is the interface needed for on-disk storage.
type File interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Sync() error
}

// File must implement pmem.File.
// It really should be exactly pmem.File but we don't want to
// expose pmem in the API definitions, so File is a copy instead.
var _ pmem.File = File(nil)

// A diskTree is an on-disk [Tree].
type diskTree struct {
	// mmu is the memory mapping mutex.
	//
	// All methods except Close do mmu.RLock and mmu.RUnlock
	// in order to be allowed to read and write pmem.Data() aka mem.
	// Note that it is OK to write the memory while holding the "RLock".
	// The point of the shared RLock is to stop Close from unmapping
	// the memory entirely.
	//
	// Close calls mmu.Lock/mmu.Unlock to wait for all other
	// method calls to finish before unmapping the memory.
	mmu  sync.RWMutex
	pmem *pmem.Mem
	mem  []byte // cache of pmem.Data()

	file1  File
	file2  File
	leaf   File
	closed bool
	err    error // sticky error
}

// broken marks the tree broken with err as the reason.
// Any method on t or function taking a t as an argument
// is expected to call t.broken for I/O or data corruption errors.
// If the error comes from another method on t or function taking t as an argument,
// then that callee can be assumed to have called t.broken.
func (t *diskTree) broken(err error) error {
	if t.err == nil {
		t.err = err
	}
	return err
}

// Create creates a new, empty on-disk [Tree] stored in the two named files.
// The files must not already exist, unless they are both os.DevNull,
// in which case the Tree is held only in memory.
func Create(file1, file2, disk string) (Tree, error) {
	return open(file1, file2, disk, os.O_WRONLY|os.O_CREATE|os.O_EXCL, "create")
}

// Open opens an on-disk [Tree] stored in the two named files.
// The files must have been created by a previous call to [Create].
func Open(file1, file2, disk string) (Tree, error) {
	return open(file1, file2, disk, os.O_RDWR, "open")
}

func open(file1, file2, file3 string, mode int, op string) (Tree, error) {
	f1, err := os.OpenFile(file1, mode, 0666)
	if err != nil {
		return nil, err
	}
	f2, err := os.OpenFile(file2, mode, 0666)
	if err != nil {
		f1.Close()
		return nil, err
	}
	if op == "create" {
		mode = os.O_RDWR | os.O_CREATE | os.O_EXCL
	}
	f3, err := os.OpenFile(file3, mode, 0666)
	if err != nil {
		f1.Close()
		f2.Close()
		return nil, err
	}
	return memOpen(f1, f2, f3, op)
}

// New creates or opens an on-disk [Tree] in the given files.
// If both files are empty, New creates a new tree in those files.
// Otherwise, New opens a pre-existing tree stored in those files.
// Only one file contains the latest tree at a time, but the
// implementation alternates between files to implement atomic updates.
func New(file1, file2, file3 File) (Tree, error) {
	var op string
	var buf [1]byte
	n1, err1 := file1.ReadAt(buf[:], 0)
	n2, err2 := file2.ReadAt(buf[:], 0)
	if n1 == 0 && n2 == 0 && err1 == io.EOF && err2 == io.EOF {
		op = "create"
	} else {
		op = "open"
	}
	return memOpen(file1, file2, file3, op)
}

// memOpen is the general implementation of open.
// op is "create", "open", or "new", indicating the operation
// being performed on the files; sync indicates whether to
// try to use the files' Sync method.
// (When using /dev/null for an in-memory tree,
// we avoid calling Sync, because it will fail.)
func memOpen(file1, file2, disk File, op string) (_ Tree, err error) {
	pmemOp := pmem.Open
	if op == "create" {
		pmemOp = pmem.Create
	}
	mem, err := pmemOp("mpt tree v3\n", file1, file2, disk)
	if err != nil {
		return nil, err
	}
	t := &diskTree{
		pmem:  mem,
		file1: file1,
		file2: file2,
		leaf:  disk,
	}
	defer func() {
		if err != nil {
			mem.Release()
			mem.UnsafeUnmap()
		}
	}()

	runtime.AddCleanup(t, func(*struct{}) { mem.Release() }, nil)

	if op == "create" {
		// Write initial tree.
		mem, err := t.pmem.Expand(hdrSize)
		if err != nil {
			return nil, err
		}
		h := emptyTreeHash
		if err := t.mutate(mem[hdrHash:], h[:]); err != nil {
			return nil, err
		}
		if err := t.pmem.Sync(); err != nil {
			return nil, err
		}
	}

	t.mem = t.pmem.Data()

	return t, nil
}

var errCorrupt = errors.New("corrupt tree data")

// Sync syncs written data to disk.
func (t *diskTree) Sync() error {
	t.mmu.RLock()
	defer t.mmu.RUnlock()

	if t.err != nil {
		return t.err
	}
	if !t.hdr().dirty() && !t.hdr().exact() {
		if err := t.hdr().setExact(t, true); err != nil {
			return err
		}
	}
	if err := t.pmem.Sync(); err != nil {
		return t.broken(err)
	}
	return nil
}

// TODO figure out whether pmem should Close.

// Close closes the tree and the files it uses.
func (t *diskTree) Close() error {
	t.mmu.Lock()
	defer t.mmu.Unlock()

	if t.closed {
		return fmt.Errorf("tree already closed")
	}
	t.closed = true
	if err := t.pmem.Sync(); err != nil {
		t.broken(err)
	}
	if err := t.pmem.Release(); err != nil {
		t.broken(err)
	}
	if err := t.pmem.UnsafeUnmap(); err != nil {
		t.broken(err)
	}
	t.mem = nil
	t.pmem = nil
	if err := t.file1.Close(); err != nil {
		t.broken(err)
	}
	if err := t.file2.Close(); err != nil {
		t.broken(err)
	}
	if err := t.leaf.Close(); err != nil {
		t.broken(err)
	}
	if t.err != nil {
		return t.err
	}
	t.err = errors.New("tree is closed") // stop future method calls
	return nil
}

// TODO: should mutate be done by editing dst in place and then calling t.mutated(dst)?

// mutate is like copy(dst, src) where dst is inside t.mem.
// It also records the mutation in the patch buffer, to be written
// to disk when the current patch block fills or Sync is called.
func (t *diskTree) mutate(dst, src []byte) error {
	n := min(len(dst), len(src))
	if err := t.pmem.Mutate(dst[:n], src[:n]); err != nil {
		return t.broken(err)
	}
	return nil
}

// addrToMem returns the tree memory at address a and length n.
func (t *diskTree) addrToMem(a addr, n int) ([]byte, error) {
	if a > addr(len(t.mem)) || len(t.mem)-int(a) < n {
		return nil, t.broken(errCorrupt)
	}
	return t.mem[a : a+addr(n)], nil
}

// memToAddr converts a byte slice p, which must be from t.mem,
// into an addr.
func (t *diskTree) memToAddr(p []byte) addr {
	off, ok := t.pmem.Offset(p)
	if !ok {
		panic("mpt: memToAddr misuse")
	}
	return addr(off)
}

// alloc allocates n more bytes of tree memory, returning it as a slice.
func (t *diskTree) alloc(n int) ([]byte, error) {
	if cap(t.mem)-len(t.mem) < n {
		mem, err := t.pmem.Expand(len(t.mem) + n)
		if err != nil {
			t.err = err
			return nil, err
		}
		t.mem = mem[:len(t.mem)]
	}
	off := len(t.mem)
	t.mem = t.mem[:off+n]
	return t.mem[off : off+n], nil
}

// An addr is an offset into the disk layout.
// It is stored on disk as a 48-bit big-endian value.
type addr uint64

// parseAddr returns the node address at the given byte offset.
func parseAddr(p []byte) addr {
	return addr(binary.BigEndian.Uint16(p))<<32 | addr(binary.BigEndian.Uint32(p[2:]))
}

// putAddr stores the node address at the given byte offset.
func putAddr(p []byte, a addr) {
	binary.BigEndian.PutUint32(p[2:], uint32(a))
	binary.BigEndian.PutUint16(p, uint16(a>>32))
}

// A ptr is a tagged pointer to a tree position, stored in the header's
// root field and in a node's left and right fields; see the Tree
// Format comment above. Both a node address (an offset in the tree
// memory) and a leaf address (an offset in the leaf file) are always
// even, since hdrSize and nodeSize are even and every leaf record is
// padded to an even length (see appendLeaf), so tagging a leaf
// address by setting its low bit, and recovering it by clearing that
// bit, never loses information. The zero ptr is nil, meaning no child.
type ptr uint64

// nodePtr returns the tagged pointer to the node at address a.
func nodePtr(a addr) ptr { return ptr(a) }

// leafPtr returns the tagged pointer to the leaf at address a
// in the leaf file.
func leafPtr(a addr) ptr { return ptr(a) | 1 }

func (p ptr) isNil() bool  { return p == 0 }
func (p ptr) isLeaf() bool { return p&1 != 0 }

// addr returns the address encoded in p: an offset into the tree
// memory if p is a node pointer, or an offset into the leaf file if
// p is a leaf pointer.
func (p ptr) addr() addr { return addr(p &^ 1) }

// parsePtr returns the tagged pointer at the given byte offset.
func parsePtr(b []byte) ptr { return ptr(parseAddr(b)) }

// putPtr stores the tagged pointer p at the given byte offset.
func putPtr(b []byte, p ptr) { putAddr(b, addr(p)) }

// A diskHdr is the memory copy of the tree header.
type diskHdr [hdrSize]byte

func (h *diskHdr) version() int64 { return int64(binary.BigEndian.Uint64(h[hdrVersion:])) }
func (h *diskHdr) dirty() bool    { return h[hdrDirty] != 0 }
func (h *diskHdr) exact() bool    { return h[hdrExact] != 0 }
func (h *diskHdr) root() ptr      { return parsePtr(h[hdrRoot:]) }
func (h *diskHdr) hash() Hash     { return Hash(h[hdrHash:]) }

func (h *diskHdr) setVersion(t *diskTree, version int64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(version))
	return t.mutate(h[hdrVersion:], buf[:])
}

func (h *diskHdr) setDirty(t *diskTree, d bool) error {
	var buf [1]byte
	if d {
		buf[0] = 1
	}
	return t.mutate(h[hdrDirty:], buf[:])
}

func (h *diskHdr) setExact(t *diskTree, d bool) error {
	var buf [1]byte
	if d {
		buf[0] = 1
	}
	return t.mutate(h[hdrExact:], buf[:])
}

func (h *diskHdr) setHash(t *diskTree, hash Hash) error {
	return t.mutate(h[hdrHash:], hash[:])
}

// hdr returns a pointer to the in-memory tree header.
func (t *diskTree) hdr() *diskHdr {
	mem, err := t.addrToMem(0, hdrSize)
	if err != nil {
		panic(err) // mem should always be big enough for the header
	}
	return (*diskHdr)(mem)
}

// A diskNode is the memory copy of a node.
// The *diskNodes passed around in this implementation
// are pointers into the in-memory copy t.mem.
type diskNode [nodeSize]byte

// node returns the diskNode at the given address.
func (t *diskTree) node(a addr) (*diskNode, error) {
	if a == 0 {
		return nil, nil
	}
	mem, err := t.addrToMem(a, nodeSize)
	if err != nil {
		return nil, err
	}
	return (*diskNode)(mem), nil
}

// addr returns the address of the given diskNode.
func (t *diskTree) addr(n *diskNode) addr {
	if n == nil {
		return 0
	}
	return t.memToAddr(n[:])
}

// addrAt reads a node address from the address a.
// The caller must ensure that a is a valid address,
// or else addrAt panics.
func (t *diskTree) addrAt(a addr) addr {
	mem, err := t.addrToMem(a, addrSize)
	if err != nil {
		panic(err)
	}
	return parseAddr(mem)
}

// setAddrAt writes the node address b to the address a.
func (t *diskTree) setAddrAt(a, b addr) error {
	mem, err := t.addrToMem(a, addrSize)
	if err != nil {
		return err
	}
	var buf [addrSize]byte
	putAddr(buf[:], b)
	return t.mutate(mem, buf[:])
}

// newNode allocates and returns a new node in the tree.
func (t *diskTree) newNode() (*diskNode, error) {
	n, err := t.alloc(nodeSize)
	if err != nil {
		return nil, err
	}
	return (*diskNode)(n), nil
}

func (n *diskNode) bitDirty() uint16 { return binary.BigEndian.Uint16(n[nodeBitDirty:]) }
func (n *diskNode) dirty() bool      { return n.bitDirty()&1 != 0 }
func (n *diskNode) left() ptr        { return parsePtr(n[nodeLeft:]) }
func (n *diskNode) right() ptr       { return parsePtr(n[nodeRight:]) }
func (n *diskNode) ihash() Hash      { return Hash(n[nodeIHash:]) }

// bit returns the bit position recorded in the node,
// the bit that decides between its left and right children.
func (n *diskNode) bit() int {
	return int(n.bitDirty() >> 1)
}

// newSplit allocates and returns a new node splitting at the given bit
// position between the left and right subtrees (each either a leaf or
// another node); it also sets dirty=true and clears ihash.
func (t *diskTree) newSplit(bit int, left, right ptr) (*diskNode, error) {
	n, err := t.newNode()
	if err != nil {
		return nil, err
	}
	var buf [nodeSize]byte
	binary.BigEndian.PutUint16(buf[nodeBitDirty:], uint16(bit)<<1|1) // bit<<1 | dirty=1
	putPtr(buf[nodeLeft:], left)
	putPtr(buf[nodeRight:], right)
	if err := t.mutate(n[:], buf[:]); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *diskNode) setIHash(t *diskTree, h Hash) error { return t.mutate(n[nodeIHash:], h[:]) }
func (n *diskNode) setDirty(t *diskTree, d bool) error {
	var buf [2]byte
	v := n.bitDirty() &^ 1 // clear dirty bit
	if d {
		v |= 1
	}
	binary.BigEndian.PutUint16(buf[:], v)
	return t.mutate(n[nodeBitDirty:], buf[:])
}

// Leaf disk is a sequence of leaf data structures, with format:
//
//	total  [2]        total length reserved for leaf
//	keylen [varint]   len(key)
//	key    [keylen]   key data
// 	vallen [varint]   len(val)
// 	val    [vallen]   val data
//
// We always allocate new leaves at the end of the disk.
// Updating a value overwrites val in place if the leaf has space.
// Otherwise it allocates a new leaf at the end of the disk and
// abandons (leaks) the old space. We expect most clients have
// fixed-length values anyway, and even those that don't only
// pay more when a value increases in size. Toggling back and forth
// between a small set of sizes reuses the space once the max size
// value has been written.
//
// We only ever overwrite the value bytes. Once the total and key
// fields are written, they are never overwritten. This way,
// after recovery it may not be safe to read the value fields,
// but reading keys is always safe. So we can support higher-level
// recovery (Version + Set) which will correct any corrupted values.
//
// For ease of pointer tagging, leaves are always an even number
// of bytes in size.

func appendLeaf(t *diskTree, key Key, val Val) error {
	buf := make([]byte, 2, 256)
	buf = binary.AppendUvarint(buf, uint64(len(key)))
	buf = append(buf, key...)
	buf = binary.AppendUvarint(buf, uint64(len(val)))
	buf = append(buf, val...)
	if len(buf)&1 == 1 {
		buf = append(buf, 0)
	}
	if len(buf) >= 1<<16 {
		// MaxKeyLen and MaxValLen should keep this from happening
		panic("overflow in setKeyVal")
	}
	binary.BigEndian.PutUint16(buf, uint16(len(buf)))

	off := t.pmem.DiskSize()
	if err := t.pmem.WriteDisk(buf, off); err != nil {
		return t.broken(err)
	}
	return nil
}

// newLeaf appends a new leaf record for key, val to the leaf file
// and returns a tagged pointer to it.
func (t *diskTree) newLeaf(key Key, val Val) (ptr, error) {
	a := addr(t.pmem.DiskSize())
	if err := appendLeaf(t, key, val); err != nil {
		return 0, err
	}
	return leafPtr(a), nil
}

// leafKey returns the key of the leaf at address a in the leaf file.
// It succeeds even if the value is corrupted.
func (t *diskTree) leafKey(a addr) (Key, error) {
	_, key, _, err := loadLeaf(t, int64(a), false)
	return key, err
}

// leafKeyVal returns the key and value of the leaf at address a
// in the leaf file.
func (t *diskTree) leafKeyVal(a addr) (Key, Val, error) {
	_, key, val, err := loadLeaf(t, int64(a), true)
	return key, val, err
}

// setLeafVal updates the value of the leaf at address a to val,
// returning the leaf's address afterward: it stays a if val fits in
// the existing allocation, or otherwise moves to a newly appended
// leaf record, whose address the caller must record in place of a.
func (t *diskTree) setLeafVal(a addr, val Val) (addr, error) {
	// Read existing key-val data in hopes of updating in place on disk.
	off := int64(a)
	buf, key, _, err := loadLeaf(t, off, false)
	if err != nil {
		return 0, err
	}
	old := len(buf)
	tn := 2 // uint16 len
	_, kn := binary.Uvarint(buf[tn:])
	vstart := tn + kn + len(key)
	buf = append(binary.AppendUvarint(buf[:vstart], uint64(len(val))), val...)
	if len(buf) <= old {
		// Overwrite existing value in place.
		if err := t.pmem.WriteDisk(buf[vstart:], off+int64(vstart)); err != nil {
			return 0, t.broken(err)
		}
		return a, nil
	}

	// Abandon storage for new leaf at end of disk.
	newAddr := addr(t.pmem.DiskSize())
	if err := appendLeaf(t, key, val); err != nil {
		return 0, err
	}
	return newAddr, nil
}

// loadLeaf loads a key-value pair from the leaf disk.
// If wantVal is false, it skips loading (and ignores any corruption in) the value.
func loadLeaf(t *diskTree, off int64, wantVal bool) (buf []byte, key Key, val Val, err error) {
	// Read initial chunk, decode total, read more if needed, and trim buf.
	limit := t.pmem.DiskSize() - off
	if limit <= 2 {
		return nil, nil, nil, t.broken(errCorrupt)
	}
	buf = make([]byte, int(min(limit, 256)))
	if err := t.pmem.ReadDisk(buf, off); err != nil {
		return nil, nil, nil, t.broken(err)
	}
	total := int(binary.BigEndian.Uint16(buf))
	if total > 2+2*binary.MaxVarintLen64+MaxKeyLen+MaxValLen || int64(total) > limit {
		return nil, nil, nil, t.broken(errCorrupt)
	}
	if len(buf) < total {
		// Need a second read for the remainder.
		n := len(buf)
		buf = slices.Grow(buf, total-n)[:total]
		if err := t.pmem.ReadDisk(buf[n:], off+int64(n)); err != nil {
			return nil, nil, nil, t.broken(errCorrupt)
		}
	}
	buf = buf[:total]

	// Decode buffer.
	i := 2 // uint16 len
	kn, kvn := binary.Uvarint(buf[i:])
	if kvn <= 0 || kn > uint64(len(buf)-i-kvn) {
		return nil, nil, nil, t.broken(errCorrupt)
	}
	i += kvn
	key = buf[i : i+int(kn)]
	i += int(kn)
	if wantVal {
		vn, vvn := binary.Uvarint(buf[i:])
		if vvn <= 0 || vn > uint64(len(buf)-i-vvn) {
			return nil, nil, nil, t.broken(errCorrupt)
		}
		i += vvn
		val = buf[i : i+int(vn)]
	}
	return buf, key, val, nil
}
