// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO test constant flushing mode

package pmem

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime/debug"
	"testing"
)

func TestRecovery(t *testing.T) {
	for i := range 10 {
		t.Run(fmt.Sprint(i), testRecovery)
	}
}

func testRecovery(t *testing.T) {
	tmp := make([]byte, 1000)

	oldPatch := maxPatch
	oldMem := maxMem
	defer func() {
		maxPatch = oldPatch
		maxMem = oldMem
	}()

	maxPatch = 256
	maxMem = 1 << 20

	tt := &tester{t: t}
	for i := range tt.file {
		tt.file[i].tester = tt
	}
	tt.disk.tester = tt
	tt.disk.isDisk = true

	mem, err := Create("magic", &tt.file[0], &tt.file[1], &tt.disk)
	if err != nil {
		t.Fatal(err)
	}
	tt.setMem(mem)
	tt.markOK()

	const (
		MaxOff   = 100
		MaxCount = 100
	)
	var diskOff int64
	for range 1000 {
		switch rand.N(12) {
		case 0, 1, 2, 3, 4:
			// Write many random memory sections,
			// more than will fit in a single patch block.
			for range 5 {
				off := rand.N(MaxOff)
				n := 1 + rand.N(MaxCount)
				tt.t.Logf("mutate %#x+%#x", off, n)
				_, err := mem.Expand(off + n)
				tt.markOK()
				check(tt.t, err)
				check(tt.t, mem.Mutate(mem.Data()[off:off+n], randFill(tmp[:n])))
			}

		case 5, 6, 7, 8:
			// Write a pair of grouped updates.
			// Have to limit to single patch block but try to use
			// almost the entire block so that a flush will be needed.
			n := maxPatch - 4*(maxVarint+1)
			n1 := 1 + rand.N(n-1)
			n2 := n - n1
			off1 := rand.N(MaxOff)
			off2 := rand.N(MaxOff)
			tt.t.Logf("begingroup (len=%#x)", len(mem.mem))
			check(tt.t, mem.BeginGroup())
			_, err := mem.Expand(off1 + n1)
			check(tt.t, err)
			tt.t.Logf("mutate %#x+%#x", off1, n1)
			check(tt.t, mem.Mutate(mem.Data()[off1:off1+n1], randFill(tmp[:n1])))
			_, err = mem.Expand(off2 + n2)
			check(tt.t, err)
			tt.t.Logf("mutate %#x+%#x", off2, n2)
			check(tt.t, mem.Mutate(mem.Data()[off2:off2+n2], randFill(tmp[:n2])))
			tt.t.Logf("endgroup")
			tt.markOK()
			check(tt.t, mem.EndGroup())

		case 9, 10:
			// Write to disk, sometimes overwriting existing data.
			dn := 1 + rand.N(20)
			off := diskOff
			if diskOff > 0 && rand.N(2) == 0 {
				off = rand.Int64N(diskOff)
			}
			tt.t.Logf("writedisk %#x+%#x", off, dn)
			tt.markOK()
			check(tt.t, mem.WriteDisk(randFill(tmp[:dn]), off))
			diskOff = max(diskOff, off+int64(dn))

		case 11:
			// Sync.
			tt.t.Logf("sync")
			check(tt.t, mem.Sync())
		}
	}

	check(t, mem.Release())
	check(t, mem.UnsafeUnmap())
}

func TestDiskSizeAfterCompaction(t *testing.T) {
	oldPatch := maxPatch
	oldMem := maxMem
	defer func() {
		maxPatch = oldPatch
		maxMem = oldMem
	}()

	maxPatch = 256
	maxMem = 1 << 16

	// Use simple testFiles with a tester that doesn't do reopens.
	// Setting tt.mem = nil prevents try() from doing anything.
	var file [2]testFile
	var disk testFile
	disk.isDisk = true

	tt := &tester{t: t}
	for i := range file {
		file[i].tester = tt
	}
	disk.tester = tt
	tt.valid = make(map[string]bool)

	mem, err := Create("magic", &file[0], &file[1], &disk)
	if err != nil {
		t.Fatal(err)
	}
	// Don't set tt.mem - this keeps try() from reopening on every write.

	// Write some disk data so diskSize > 0.
	diskData := make([]byte, 50)
	randFill(diskData)
	check(t, mem.WriteDisk(diskData, 0))
	if mem.DiskSize() != 50 {
		t.Fatalf("DiskSize = %d, want 50", mem.DiskSize())
	}

	// Write enough memory mutations to trigger compaction.
	// Compaction starts when the current file exceeds 2× the tree size.
	// With maxPatch=256 and small memory, a few flushes will do it.
	tmp := make([]byte, 100)
	for i := range 200 {
		off := i % 50
		_, err := mem.Expand(off + 100)
		check(t, err)
		check(t, mem.Mutate(mem.Data()[off:off+100], randFill(tmp)))
	}
	// Sync to finalize any in-progress compaction.
	check(t, mem.Sync())

	wantDiskSize := mem.DiskSize()
	if wantDiskSize != 50 {
		t.Fatalf("DiskSize before reopen = %d, want 50", wantDiskSize)
	}

	// Simulate a crash by reopening from the current file state.
	diskClone := disk.clone()
	diskClone.tester = tt
	diskClone.isDisk = true
	mem2, err := Open("magic", file[0].clone(), file[1].clone(), diskClone)
	if err != nil {
		t.Fatalf("reopen after compaction: %v", err)
	}
	if mem2.DiskSize() != wantDiskSize {
		t.Fatalf("after compaction reopen: DiskSize = %d, want %d", mem2.DiskSize(), wantDiskSize)
	}
	check(t, mem2.Release())
	check(t, mem2.UnsafeUnmap())

	check(t, mem.Release())
	check(t, mem.UnsafeUnmap())
}

func TestWriteAfterOpen(t *testing.T) {
	tt := &tester{t: t}
	for i := range tt.file {
		tt.file[i].tester = tt
	}
	tt.disk.tester = tt
	tt.disk.isDisk = true

	m, err := Create("magic", &tt.file[0], &tt.file[1], &tt.disk)
	if err != nil {
		t.Fatal(err)
	}
	tt.setMem(m)
	createdID := m.id
	if createdID == [16]byte{} {
		t.Fatal("created ID is zero")
	}
	first := []byte("written before reopen")
	_, err = m.Expand(len(first))
	check(t, err)
	check(t, m.Mutate(m.Data(), first))
	firstDisk := []byte("disk data")
	check(t, m.WriteDisk(firstDisk, 0))
	check(t, m.Sync())
	check(t, m.Release())
	check(t, m.UnsafeUnmap())

	m, err = Open("magic", &tt.file[0], &tt.file[1], &tt.disk)
	if err != nil {
		t.Fatal(err)
	}
	tt.setMem(m)
	if m.id != createdID {
		t.Errorf("opened ID %x != created ID %x", m.id, createdID)
	}
	if !bytes.Equal(m.Data(), first) {
		t.Errorf("opened data %q, want %q", m.Data(), first)
	}
	if m.DiskSize() != int64(len(firstDisk)) {
		t.Errorf("opened DiskSize %d, want %d", m.DiskSize(), len(firstDisk))
	}

	// Frames written after Open carry m.id, so if Open did not restore it
	// from the files, the writes below would be stamped with a zero ID and
	// dropped (or rejected) by the next Open.
	second := []byte("written after reopen, longer than the first write")
	_, err = m.Expand(len(second))
	check(t, err)
	check(t, m.Mutate(m.Data(), second))
	secondDisk := []byte("disk data written after reopen")
	check(t, m.WriteDisk(secondDisk, 0))
	check(t, m.Sync())
	check(t, m.Release())
	check(t, m.UnsafeUnmap())

	diskClone := tt.disk.clone()
	diskClone.tester = tt // writable, for patch replay
	diskClone.isDisk = true
	m2, err := Open("magic", tt.file[0].clone(), tt.file[1].clone(), diskClone)
	if err != nil {
		t.Fatal(err)
	}
	if m2.id != createdID {
		t.Errorf("reopened ID %x != created ID %x", m2.id, createdID)
	}
	if !bytes.Equal(m2.Data(), second) {
		t.Errorf("reopened data %q, want %q", m2.Data(), second)
	}
	if m2.DiskSize() != int64(len(secondDisk)) {
		t.Errorf("reopened DiskSize %d, want %d", m2.DiskSize(), len(secondDisk))
	}
	gotDisk := make([]byte, len(secondDisk))
	check(t, m2.ReadDisk(gotDisk, 0))
	if !bytes.Equal(gotDisk, secondDisk) {
		t.Errorf("reopened disk data %q, want %q", gotDisk, secondDisk)
	}
	check(t, m2.Release())
	check(t, m2.UnsafeUnmap())
}

func randFill(b []byte) []byte {
	for i := range b {
		b[i] = byte(rand.N(256))
	}
	return b
}

type tester struct {
	t         *testing.T
	mem       *Mem
	file      [2]testFile
	disk      testFile
	valid     map[string]bool                // hashes of acceptable memory images
	validDisk map[string]map[int64][]byteSet // for each mem hash & valid disk size, valid disk bytes by offset
}

// byteSet is a bitmap of 256 bits, one per possible byte value.
type byteSet [4]uint64

func (s *byteSet) add(b byte)      { s[b/64] |= 1 << (b % 64) }
func (s *byteSet) has(b byte) bool { return s[b/64]&(1<<(b%64)) != 0 }

type testFile struct {
	tester  *tester
	data    []byte // data in file
	sync    int    // offset of last sync; writes only append
	current bool   // whether file is current
	isDisk  bool   // whether this is a disk file (not a memory file)
}

func (f *testFile) setCurrent(current bool, off int) {
	f.current = current
	f.data = f.data[:off]
}

func (f *testFile) clone() *testFile {
	return &testFile{data: bytes.Clone(f.data)}
}

// ReadAt reads from the test file.
func (f *testFile) ReadAt(data []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(data, f.data[off:])
	if n < len(data) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

// WriteAt writes to the test file.
func (f *testFile) WriteAt(data []byte, off int64) (int, error) {
	if f.tester == nil {
		panic("write to read-only file")
	}

	// Writes to the current file should only ever append;
	// not overwriting is part of our reliability story.
	// Writes to the next file can be scattered, because
	// we are writing the tree interleaved with new patches.
	if f.current && off != int64(len(f.data)) {
		return 0, fmt.Errorf("non-appending write\n\n%s", debug.Stack())
	}
	if off > int64(len(f.data)) {
		// Fill hole in file.
		f.data = append(f.data, make([]byte, int(off)-len(f.data))...)
	}
	f.tester.t.Logf("%s write %#x+%#x = %#x", f.name(), off, len(data), off+int64(len(data)))
	n := copy(f.data[off:], data)
	f.data = append(f.data, data[n:]...)

	// Try corrupting the writes and see what happens.
	// Only test memory files; disk file integrity doesn't affect recovery.
	if !f.isDisk {
		f.tester.try(f)
	}

	return len(data), nil
}

// Close closes the test file.
func (f *testFile) Close() error {
	return nil
}

func (f *testFile) name() string {
	if f.tester == nil {
		return "???"
	}
	if f == &f.tester.file[0] {
		return "file0"
	}
	if f == &f.tester.file[1] {
		return "file1"
	}
	return "disk"
}

// Sync syncs the test file.
// After Sync, bytes before the current offset cannot be lost or corrupted.
func (f *testFile) Sync() error {
	if f.tester == nil {
		return nil
	}

	f.sync = len(f.data)
	f.tester.t.Logf("%s sync at %#x", f.name(), f.sync)
	if !f.isDisk {
		f.tester.try(f)
	}
	return nil
}

func (tt *tester) setMem(mem *Mem) {
	tt.mem = mem
	mem.syncHook = tt.syncHook
	mem.mutateHook = tt.markOK
	if tt.valid == nil {
		tt.valid = make(map[string]bool)
	}
	if tt.validDisk == nil {
		tt.validDisk = make(map[string]map[int64][]byteSet)
	}
	tt.markOK()
}

func (tt *tester) markOK() {
	tt.t.Helper()
	h := tt.mem.hash()
	tt.t.Logf("ok %s", h)
	tt.valid[h] = true

	// Track valid disk sizes and byte values for this memory state.
	//
	// When recovery restores memory image h, patch replay resets the disk
	// bytes written up through h to their values as of h. But bytes written
	// only by later (discarded) transactions may still survive on disk,
	// because physical disk writes are never undone. So the bytes valid for
	// (h, size) are the bytes as of (h, size), plus the bytes from every state
	// that follows it up to the next sync.
	//
	// We build this incrementally: at each state we OR the current disk bytes
	// into the byte sets of every (h, size) pair seen since the last sync.
	if tt.validDisk[h] == nil {
		tt.validDisk[h] = make(map[int64][]byteSet)
	}
	size := tt.mem.DiskSize()
	if _, ok := tt.validDisk[h][size]; !ok {
		tt.validDisk[h][size] = make([]byteSet, size)
	}

	if tt.mem.disk != nil && size > 0 {
		data := make([]byte, size)
		tt.mem.disk.ReadAt(data, tt.mem.diskOff)

		for _, sizes := range tt.validDisk {
			for s, vd := range sizes {
				for i := int64(0); i < s && i < size; i++ {
					vd[i].add(data[i])
				}
			}
		}
	}
}

func (tt *tester) syncHook() {
	clear(tt.valid) // older snapshots no longer acceptable
	clear(tt.validDisk)
	tt.markOK()
}

// try tries reopening the files with various i/o problems.
func (tt *tester) try(f *testFile) {
	if tt.mem == nil {
		// Initial tree not created yet.
		return
	}

	tt.reopen("as written")

	// Test file truncated to last sync.
	whole := f.data
	f.data = whole[:f.sync]
	tt.reopen("truncated to last sync at %#x", f.sync)

	// Test file truncated past the sync point.
	if n := len(whole) - f.sync; n >= 2 {
		for range 5 {
			pos := f.sync + 1 + rand.N(n-1)
			f.data = whole[:pos]
			tt.reopen("truncated to %#x", pos)
		}
	}

	// Test file with correct length but corrupt data past the sync point.
	f.data = whole
	if len(f.data) > f.sync {
		for range 5 {
			pos := f.sync + rand.N(len(f.data)-f.sync)
			f.data[pos] ^= 1
			tt.reopen("corrupted at %#x", pos)
			f.data[pos] ^= 1
		}
	}

	// Test file with write actually succeeding.
	tt.reopen("as written")
}

func (tt *tester) reopen(format string, args ...any) {
	kind := fmt.Sprintf(format, args...)
	diskClone := tt.disk.clone()
	diskClone.tester = tt // writable, for patch replay
	diskClone.isDisk = true
	mem, err := Open("magic", tt.file[0].clone(), tt.file[1].clone(), diskClone)
	if err != nil {
		tt.t.Fatalf("reopen: %s: %v\n\n%s", kind, err, hex.Dump(tt.file[0].data))
	}
	h := mem.hash()
	if !tt.valid[h] {
		tt.t.Fatalf("reopen (%d %d): %s: invalid hash %v want %v\n\n%s\n\n%s\n\n%s", len(tt.file[0].data), len(tt.file[1].data), kind, h, tt.valid, debug.Stack(), hex.Dump(tt.mem.mem), hex.Dump(mem.mem))
	}

	// Check disk size and bytes are valid for this recovered memory image.
	vd, ok := tt.validDisk[h][mem.diskSize]
	if !ok {
		var validSizes []int64
		for s := range tt.validDisk[h] {
			validSizes = append(validSizes, s)
		}
		tt.t.Fatalf("reopen (%d %d): %s: invalid diskSize %d for hash %s, want one of %v", len(tt.file[0].data), len(tt.file[1].data), kind, mem.diskSize, h, validSizes)
	}

	if mem.diskSize > 0 {
		data := make([]byte, mem.diskSize)
		mem.disk.ReadAt(data, mem.diskOff)
		for i, b := range data {
			if !vd[i].has(b) {
				tt.t.Fatalf("reopen (%d %d): %s: invalid disk byte %#x at offset %d (hash %s, diskSize %d)", len(tt.file[0].data), len(tt.file[1].data), kind, b, i, h, mem.diskSize)
			}
		}
	}

	check(tt.t, mem.Release())
	check(tt.t, mem.UnsafeUnmap())
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
