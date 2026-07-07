// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Gen generates testdata/verify.txt, a file of test vectors for [mpt.Verify].
//
// Usage:
//
//	go run testdata/gen.go > testdata/verify.txt
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"

	"filippo.io/torchwood/mpt"
)

func main() {
	var g gen
	g.header()
	g.emptyTree()
	g.singleLeaf()
	g.twoLeaves()
	g.threeLeaves()
	g.corruption()
	g.varLenKeys()
	g.keyOverlap()
	g.emptyKeyVal()
	g.proofStructure()
	if _, err := os.Stdout.WriteString(g.String()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// gen accumulates test output.
type gen struct {
	buf bytes.Buffer
}

func (g *gen) String() string { return g.buf.String() }

// Output methods.

func (g *gen) printf(format string, args ...any) {
	fmt.Fprintf(&g.buf, format, args...)
}

func (g *gen) comment(lines string) {
	for _, line := range strings.Split(lines, "\n") {
		if line == "" {
			g.printf("#\n")
		} else {
			g.printf("# %s\n", line)
		}
	}
}

func (g *gen) blank() { g.printf("\n") }

func (g *gen) section(title string) {
	g.printf("# === %s ===\n\n", title)
}

func (g *gen) snap(h mpt.Hash) {
	g.printf("snap %s\n", encHex(h[:]))
}

func (g *gen) key(k []byte) {
	if len(k) == 0 {
		g.printf("key ''\n")
		return
	}
	g.printf("key %s\n", encHex(k))
}

func (g *gen) val(v []byte) {
	if len(v) == 0 {
		g.printf("val ''\n")
		return
	}
	g.printf("val %s\n", encHex(v))
}

func (g *gen) valAbsent() {
	g.printf("val -\n")
}

// proof writes a formatted proof line.
// ok indicates whether this is a presence proof (true) or absence proof (false),
// which affects how the proof bytes are parsed for display formatting.
func (g *gen) proof(p mpt.Proof, ok bool) {
	if len(p) == 0 {
		g.printf("proof ''\n")
		return
	}
	groups := fmtGroups([]byte(p), ok)
	if len(groups) == 1 {
		g.printf("proof %s\n", groups[0])
		return
	}
	for i, gr := range groups {
		switch {
		case i == 0:
			g.printf("proof %s \\\n", gr)
		case i < len(groups)-1:
			g.printf("\t%s \\\n", gr)
		default:
			g.printf("\t%s\n", gr)
		}
	}
}

// rawProof writes a proof as unformatted hex on one line.
// Use for corrupted proofs that cannot be parsed structurally.
func (g *gen) rawProof(p []byte) {
	if len(p) == 0 {
		g.printf("proof ''\n")
	} else {
		g.printf("proof %s\n", encHex(p))
	}
}

func (g *gen) verify(want bool) {
	g.printf("verify %v\n", want)
}

// encHex formats bytes as a hex string.
func encHex(b []byte) string {
	return hex.EncodeToString(b)
}

// fmtGroups splits raw proof bytes into display groups.
// Each group is a space-separated hex string that should appear on one line.
func fmtGroups(data []byte, ok bool) []string {
	var groups []string
	if !ok {
		// altkey: varint(len) key
		keyLen, n := binary.Uvarint(data)
		groups = append(groups, encHex(data[:n])+" "+encHex(data[n:n+int(keyLen)]))
		data = data[n+int(keyLen):]
		// altval: varint(len) val
		valLen, n := binary.Uvarint(data)
		groups = append(groups, encHex(data[:n])+" "+encHex(data[n:n+int(valLen)]))
		data = data[n+int(valLen):]
	}
	// path steps: varint(bit) + 32-byte hash
	for len(data) > 0 {
		_, n := binary.Uvarint(data)
		groups = append(groups, encHex(data[:n])+" "+encHex(data[n:n+32]))
		data = data[n+32:]
	}
	return groups
}

// Tree helpers.

func tkey(name string) mpt.Key { return sha256.Sum256([]byte("key:" + name)) }
func tval(name string) mpt.Val { return sha256.Sum256([]byte("val:" + name)) }

// fixture is a tree with a snapshot, ready for proving.
type fixture struct {
	tree mpt.Tree
	snap mpt.Snapshot
}

func newFixture(names ...string) *fixture {
	t := mpt.NewMemTree()
	for _, name := range names {
		t.Set(tkey(name), tval(name))
	}
	v := int64(1)
	if len(names) == 0 {
		v = 0
	}
	snap, err := t.Snap(v)
	if err != nil {
		panic(err)
	}
	return &fixture{tree: t, snap: snap}
}

func (f *fixture) prove(key mpt.Key) (mpt.Val, bool, mpt.Proof) {
	v, ok, p, err := f.tree.Prove(key)
	if err != nil {
		panic(err)
	}
	return v, ok, p
}

// Proof mutation helpers.

func truncated(p mpt.Proof, n int) mpt.Proof {
	return slices.Clone(p)[:n]
}

func flipped(p mpt.Proof, byteIdx int) mpt.Proof {
	q := slices.Clone(p)
	q[byteIdx] ^= 0x80
	return q
}

func appended(p mpt.Proof, b byte) mpt.Proof {
	return append(slices.Clone(p), b)
}

// Variable-length key helpers.

func vhashLeaf(key, val []byte) mpt.Hash {
	h := sha256.New()
	h.Write([]byte{0})
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(key)))
	h.Write(buf[:n])
	h.Write(key)
	n = binary.PutUvarint(buf[:], uint64(len(val)))
	h.Write(buf[:n])
	h.Write(val)
	return mpt.Hash(h.Sum(nil))
}

func vhashInner(bit int, left, right mpt.Hash) mpt.Hash {
	h := sha256.New()
	h.Write([]byte{1})
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(bit))
	h.Write(buf[:n])
	h.Write(left[:])
	h.Write(right[:])
	return mpt.Hash(h.Sum(nil))
}

type pathStep struct {
	bit  int
	hash mpt.Hash
}

func buildDenyProof(altkey, altval []byte, steps []pathStep) mpt.Proof {
	var p mpt.Proof
	p = binary.AppendUvarint(p, uint64(len(altkey)))
	p = append(p, altkey...)
	p = binary.AppendUvarint(p, uint64(len(altval)))
	p = append(p, altval...)
	for _, s := range steps {
		p = binary.AppendUvarint(p, uint64(s.bit))
		p = append(p, s.hash[:]...)
	}
	return p
}

func buildConfirmProof(steps []pathStep) mpt.Proof {
	var p mpt.Proof
	for _, s := range steps {
		p = binary.AppendUvarint(p, uint64(s.bit))
		p = append(p, s.hash[:]...)
	}
	return p
}

// Test generation methods.

func (g *gen) header() {
	g.comment("Test vectors for mpt.Verify, generated by gen.go.")
	g.comment("")
	g.comment("Each test sets state with snap, key, val, and proof lines,")
	g.comment("then calls verify to check the result. Blank lines and lines")
	g.comment("beginning with # are ignored.")
	g.comment("")
	g.comment("Format:")
	g.comment("  snap HEXHASH        - set the snapshot hash")
	g.comment("  key HEXKEY          - set the lookup key")
	g.comment("  val HEXVAL          - set val and ok=true")
	g.comment("  val -               - set val to empty and ok=false")
	g.comment("  proof HEXPROOF      - set the proof (hex bytes, spaces ok)")
	g.comment("  proof ''            - set the proof to empty (zero-length)")
	g.comment("  verify true         - Verify should succeed (return nil)")
	g.comment("  verify false        - Verify should fail (return error)")
	g.comment("")
	g.comment("Proof lines may be continued with \\ at end of line;")
	g.comment("continuation lines conventionally start with a tab.")
	g.comment("The hex for snap, key, val, and proof may contain spaces.")
	g.comment("")
	g.comment("DO NOT EDIT. Generated by:")
	g.comment("  go run testdata/gen.go > testdata/verify.txt")
	g.blank()
}

func (g *gen) emptyTree() {
	g.section("Empty tree")

	f := newFixture()
	k := tkey("missing")

	g.comment("Absent key: empty proof is valid for empty tree.")
	g.snap(f.snap.Hash)
	g.key(k[:])
	g.valAbsent()
	g.proof(mpt.Proof{}, false)
	g.verify(true)
	g.blank()

	g.comment("Absent key: empty proof is invalid for non-empty snapshot.")
	g.snap(sha256.Sum256([]byte("wrong")))
	g.key(k[:])
	g.valAbsent()
	g.proof(mpt.Proof{}, false)
	g.verify(false)
	g.blank()
}

func (g *gen) singleLeaf() {
	g.section("Single-leaf tree")

	f := newFixture("a")
	ka, va := tkey("a"), tval("a")
	km := tkey("missing")

	g.comment("Present key: valid proof (no path steps for single leaf).")
	_, _, pp := f.prove(ka)
	g.snap(f.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.proof(pp, true)
	g.verify(true)
	g.blank()

	g.comment("Present key: wrong value, same proof.")
	g.snap(f.snap.Hash)
	g.key(ka[:])
	wrongVal := tval("wrong")
	g.val(wrongVal[:])
	g.proof(pp, true)
	g.verify(false)
	g.blank()

	g.comment("Absent key: valid non-existence proof.")
	_, _, dp := f.prove(km)
	g.snap(f.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(true)
	g.blank()

	g.comment("Absent key: valid proof but wrong snapshot.")
	g.snap(sha256.Sum256([]byte("wrong")))
	g.key(km[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(false)
	g.blank()
}

func (g *gen) twoLeaves() {
	g.section("Two-leaf tree")

	f := newFixture("a", "b")
	ka, va := tkey("a"), tval("a")
	kb, vb := tkey("b"), tval("b")
	km := tkey("missing")

	g.comment("Present key a: one path step.")
	_, _, pa := f.prove(ka)
	g.snap(f.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.proof(pa, true)
	g.verify(true)
	g.blank()

	g.comment("Present key b: one path step.")
	_, _, pb := f.prove(kb)
	g.snap(f.snap.Hash)
	g.key(kb[:])
	g.val(vb[:])
	g.proof(pb, true)
	g.verify(true)
	g.blank()

	g.comment("Absent key: non-existence proof with path.")
	_, _, dp := f.prove(km)
	g.snap(f.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(true)
	g.blank()
}

func (g *gen) threeLeaves() {
	g.section("Three-leaf tree")

	f := newFixture("a", "b", "c")
	ka, va := tkey("a"), tval("a")
	kb, vb := tkey("b"), tval("b")
	kc, vc := tkey("c"), tval("c")
	km := tkey("missing")

	g.comment("Present key a.")
	_, _, pa := f.prove(ka)
	g.snap(f.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.proof(pa, true)
	g.verify(true)
	g.blank()

	g.comment("Present key b.")
	_, _, pb := f.prove(kb)
	g.snap(f.snap.Hash)
	g.key(kb[:])
	g.val(vb[:])
	g.proof(pb, true)
	g.verify(true)
	g.blank()

	g.comment("Present key c.")
	_, _, pc := f.prove(kc)
	g.snap(f.snap.Hash)
	g.key(kc[:])
	g.val(vc[:])
	g.proof(pc, true)
	g.verify(true)
	g.blank()

	g.comment("Absent key.")
	_, _, dp := f.prove(km)
	g.snap(f.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(true)
	g.blank()
}

func (g *gen) corruption() {
	g.section("Corrupted proofs")

	f2 := newFixture("a", "b")
	ka, va := tkey("a"), tval("a")
	km := tkey("missing")

	_, _, pa := f2.prove(ka)
	_, _, dp := f2.prove(km)

	g.comment("Flipped bit in sibling hash.")
	g.snap(f2.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.rawProof(flipped(pa, len(pa)-1))
	g.verify(false)
	g.blank()

	g.comment("Extra trailing byte.")
	g.snap(f2.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.rawProof(appended(pa, 0x00))
	g.verify(false)
	g.blank()

	if len(pa) > 1 {
		g.comment("Truncated proof: only varint, no hash.")
		g.snap(f2.snap.Hash)
		g.key(ka[:])
		g.val(va[:])
		g.rawProof(truncated(pa, 1))
		g.verify(false)
		g.blank()
	}

	g.comment("Empty proof for non-empty tree (presence claim).")
	g.snap(f2.snap.Hash)
	g.key(ka[:])
	g.val(va[:])
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	g.comment("Truncated non-existence proof: altkey but no altval.")
	// Build a truncated deny proof: varint(32) + key only, missing val.
	trunc := make([]byte, 0, 64)
	trunc = binary.AppendUvarint(trunc, 32)
	trunc = append(trunc, ka[:]...)
	g.snap(f2.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.rawProof(trunc)
	g.verify(false)
	g.blank()

	g.comment("Non-existence proof where altkey equals lookup key.")
	fakeProof := buildDenyProof(km[:], va[:], nil)
	g.snap(f2.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.rawProof(fakeProof)
	g.verify(false)
	g.blank()

	g.comment("Flipped bit in altkey of non-existence proof.")
	g.snap(f2.snap.Hash)
	g.key(km[:])
	g.valAbsent()
	g.rawProof(flipped(dp, 1)) // flip in altkey data
	g.verify(false)
	g.blank()

	f3 := newFixture("a", "b", "c")
	ka3 := tkey("a")
	va3 := tval("a")
	_, _, pa3 := f3.prove(ka3)

	if len(pa3) > 33 {
		g.comment("Truncated multi-step proof: cut after first path step.")
		g.snap(f3.snap.Hash)
		g.key(ka3[:])
		g.val(va3[:])
		g.rawProof(truncated(pa3, 33))
		g.verify(false)
		g.blank()
	}
}

func (g *gen) varLenKeys() {
	g.section("Variable-length keys")

	// Single leaf with 1-byte key.
	shortKey := []byte{0xFF}
	shortVal := []byte{0x42}
	treeHash := vhashLeaf(shortKey, shortVal)

	g.comment("Short (1-byte) altkey: single-leaf tree, absent 32-byte key.")
	var lk mpt.Key
	lk[0] = 0xFE
	dp := buildDenyProof(shortKey, shortVal, nil)
	g.snap(treeHash)
	g.key(lk[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(true)
	g.blank()

	// Two-leaf tree: short key (left) + normal key (right).
	shortKey2 := []byte{0x00}
	shortVal2 := []byte{0xAA}
	var normalKey mpt.Key
	normalKey[0] = 0x80
	var normalVal mpt.Val
	for i := range normalVal {
		normalVal[i] = 0xBB
	}
	lHash := vhashLeaf(shortKey2, shortVal2)
	rHash := vhashLeaf(normalKey[:], normalVal[:])
	rootHash := vhashInner(0, lHash, rHash)

	g.comment("Short altkey in two-leaf tree: lookup on left side.")
	var lk2 mpt.Key
	lk2[0] = 0x01 // bit 0 = 0, same side as shortKey2
	dp2 := buildDenyProof(shortKey2, shortVal2, []pathStep{{0, rHash}})
	g.snap(rootHash)
	g.key(lk2[:])
	g.valAbsent()
	g.proof(dp2, false)
	g.verify(true)
	g.blank()

	g.comment("Normal-length altkey in two-leaf tree: lookup on right side.")
	var lk3 mpt.Key
	lk3[0] = 0xC0 // bit 0 = 1, same side as normalKey
	dp3 := buildDenyProof(normalKey[:], normalVal[:], []pathStep{{0, lHash}})
	g.snap(rootHash)
	g.key(lk3[:])
	g.valAbsent()
	g.proof(dp3, false)
	g.verify(true)
	g.blank()

	// Single leaf with long key (64 bytes).
	longKey := make([]byte, 64)
	longKey[0] = 0x80
	for i := 1; i < len(longKey); i++ {
		longKey[i] = 0xFF
	}
	longVal := []byte{0x99, 0x88}
	longTreeHash := vhashLeaf(longKey, longVal)

	g.comment("Long (64-byte) altkey: single-leaf tree, absent 32-byte key.")
	var lk4 mpt.Key
	lk4[0] = 0x81
	dp4 := buildDenyProof(longKey, longVal, nil)
	g.snap(longTreeHash)
	g.key(lk4[:])
	g.valAbsent()
	g.proof(dp4, false)
	g.verify(true)
	g.blank()

	// Variable-length value: short key AND short val.
	shortKey3 := []byte{0xAB, 0xCD}
	shortVal3 := []byte{0x01, 0x02, 0x03}
	treeHash3 := vhashLeaf(shortKey3, shortVal3)

	g.comment("Short altkey and short altval (2-byte key, 3-byte val).")
	var lk5 mpt.Key
	lk5[0] = 0xAB
	lk5[1] = 0xCE // differs from shortKey3
	dp5 := buildDenyProof(shortKey3, shortVal3, nil)
	g.snap(treeHash3)
	g.key(lk5[:])
	g.valAbsent()
	g.proof(dp5, false)
	g.verify(true)
	g.blank()

	// Confirm proof with variable-length key (key present).
	g.comment("Short key present in single-leaf tree (1-byte key, 1-byte val).")
	shortKey4 := []byte{0xDD}
	shortVal4 := []byte{0xEE}
	treeHash4 := vhashLeaf(shortKey4, shortVal4)
	g.snap(treeHash4)
	g.key(shortKey4)
	g.val(shortVal4)
	g.proof(mpt.Proof{}, true) // single leaf, no path steps
	g.verify(true)
	g.blank()

	// Short key present in two-leaf tree.
	leftKey := []byte{0x10}
	leftVal := []byte{0xAA, 0xBB}
	rightKey := []byte{0x90}
	rightVal := []byte{0xCC}
	lh := vhashLeaf(leftKey, leftVal)
	rh := vhashLeaf(rightKey, rightVal)
	root := vhashInner(0, lh, rh)

	g.comment("Short key present in two-leaf tree: left child (1-byte key, 2-byte val).")
	g.snap(root)
	g.key(leftKey)
	g.val(leftVal)
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(true)
	g.blank()

	g.comment("Short key present in two-leaf tree: right child (1-byte key, 1-byte val).")
	g.snap(root)
	g.key(rightKey)
	g.val(rightVal)
	g.proof(buildConfirmProof([]pathStep{{0, lh}}), true)
	g.verify(true)
	g.blank()

	// Invalid: wrong tree hash with short altkey.
	g.comment("Short altkey: wrong tree hash.")
	g.snap(sha256.Sum256([]byte("wrong")))
	g.key(lk[:])
	g.valAbsent()
	g.proof(dp, false)
	g.verify(false)
	g.blank()

	// Invalid: bit mismatch between lookup key and short altkey.
	g.comment("Short altkey: bit mismatch in path (altkey on wrong side).")
	var lkWrong mpt.Key
	lkWrong[0] = 0xC0 // bit 0 = 1, but shortKey2 bit 0 = 0
	dpWrong := buildDenyProof(shortKey2, shortVal2, []pathStep{{0, rHash}})
	g.snap(rootHash)
	g.key(lkWrong[:])
	g.valAbsent()
	g.proof(dpWrong, false)
	g.verify(false)
	g.blank()
}

func (g *gen) keyOverlap() {
	g.section("Key overlap (K vs K||0x00)")
	g.comment("Keys are padded with a 0x00 byte followed by 0xFF bytes.")
	g.comment("This means K and K||0x00 have different bit patterns")
	g.comment("and can coexist in the same tree.")
	g.blank()

	// K = {0xFF}, K0 = {0xFF, 0x00}.
	// K pads to:  FF 00 FF FF... (0x00 pad then 0xFF)
	// K0 pads to: FF 00 00 FF... (0x00 pad then 0xFF)
	// They agree through bit 15 and differ at bit 16.
	K := []byte{0xFF}
	K0 := []byte{0xFF, 0x00}
	Kval := []byte{0x42}
	K0val := []byte{0x99}

	// --- Tree containing K ---
	Khash := vhashLeaf(K, Kval)

	g.comment("K={FF} stored. Lookup K: present.")
	g.snap(Khash)
	g.key(K)
	g.val(Kval)
	g.proof(mpt.Proof{}, true)
	g.verify(true)
	g.blank()

	g.comment("K={FF} stored. Lookup K0={FF00}: absent (lands at K's leaf).")
	dpK0 := buildDenyProof(K, Kval, nil)
	g.snap(Khash)
	g.key(K0)
	g.valAbsent()
	g.proof(dpK0, false)
	g.verify(true)
	g.blank()

	g.comment("K={FF} stored. Existence proof for K must NOT verify K0 as present.")
	g.snap(Khash)
	g.key(K0)
	g.val(Kval)
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// --- Tree containing K0 ---
	K0hash := vhashLeaf(K0, K0val)

	g.comment("K0={FF00} stored. Lookup K0: present.")
	g.snap(K0hash)
	g.key(K0)
	g.val(K0val)
	g.proof(mpt.Proof{}, true)
	g.verify(true)
	g.blank()

	g.comment("K0={FF00} stored. Lookup K={FF}: absent (lands at K0's leaf).")
	dpK := buildDenyProof(K0, K0val, nil)
	g.snap(K0hash)
	g.key(K)
	g.valAbsent()
	g.proof(dpK, false)
	g.verify(true)
	g.blank()

	g.comment("K0={FF00} stored. Existence proof for K0 must NOT verify K as present.")
	g.snap(K0hash)
	g.key(K)
	g.val(K0val)
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// --- Same tests with a two-leaf tree to exercise path steps ---
	// Left: K={0x10}, Right: {0x90, 0xAA}
	Kp := []byte{0x10}
	KpVal := []byte{0xBB}
	Kp0 := []byte{0x10, 0x00}
	other := []byte{0x90, 0xAA}
	otherVal := []byte{0xCC, 0xDD}

	lh := vhashLeaf(Kp, KpVal)
	rh := vhashLeaf(other, otherVal)
	root := vhashInner(0, lh, rh)

	g.comment("Two-leaf tree with K={10}. Lookup K: present.")
	g.snap(root)
	g.key(Kp)
	g.val(KpVal)
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(true)
	g.blank()

	g.comment("Two-leaf tree with K={10}. Lookup K0={1000}: absent.")
	dpKp0 := buildDenyProof(Kp, KpVal, []pathStep{{0, rh}})
	g.snap(root)
	g.key(Kp0)
	g.valAbsent()
	g.proof(dpKp0, false)
	g.verify(true)
	g.blank()

	g.comment("Two-leaf tree with K={10}. Existence proof for K must NOT verify K0={1000}.")
	g.snap(root)
	g.key(Kp0)
	g.val(KpVal)
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(false)
	g.blank()

	// --- Padding allows K and K0 to coexist in the same tree ---
	// With 0x00+0xFF padding, K={0xFF} pads to FF 00 FF FF...,
	// while K0={0xFF,0x00} pads to FF 00 00 FF FF...
	// They agree through bit 15 and split at bit 16:
	// K has 1 (0xFF zone), K0 has 0 (0x00 padding byte).
	Kboth := []byte{0xFF}
	KbothVal := []byte{0x42}
	K0both := []byte{0xFF, 0x00}
	K0bothVal := []byte{0x99}
	KbothLeaf := vhashLeaf(Kboth, KbothVal)
	K0bothLeaf := vhashLeaf(K0both, K0bothVal)
	// K has bit 16 = 1 (0xFF zone), so K is on the right.
	// K0 has bit 16 = 0 (0x00 padding byte), so K0 is on the left.
	bothRoot := vhashInner(16, K0bothLeaf, KbothLeaf)

	g.comment("K={FF} and K0={FF00} coexist: split at bit 16. Lookup K: present (right child).")
	g.snap(bothRoot)
	g.key(Kboth)
	g.val(KbothVal)
	g.proof(buildConfirmProof([]pathStep{{16, K0bothLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("K={FF} and K0={FF00} coexist: lookup K0: present (left child).")
	g.snap(bothRoot)
	g.key(K0both)
	g.val(K0bothVal)
	g.proof(buildConfirmProof([]pathStep{{16, KbothLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("K={FF} and K0={FF00} coexist: lookup {FE}: absent.")
	var lookupFE [1]byte
	lookupFE[0] = 0xFE
	// {FE} pads to FE 00 FF FF..., K pads to FF 00 FF FF...
	// At bit 16: {FE} has 1 (0xFF zone), K has 1 (0xFF zone). Same side (right).
	// Deny proof has altkey=K, path step at bit 16.
	dpFE := buildDenyProof(Kboth, KbothVal, []pathStep{{16, K0bothLeaf}})
	g.snap(bothRoot)
	g.key(lookupFE[:])
	g.valAbsent()
	g.proof(dpFE, false)
	g.verify(true)
	g.blank()

	// --- Empty key coexists with {0x00} ---
	// Empty pads to 00 FF FF..., {0x00} pads to 00 00 FF FF...
	// They agree at bits 0-7 (both 0x00) and split at bit 8:
	// empty has 1 (0xFF zone), {0x00} has 0 (0x00 padding byte).
	emptyKCoexist := []byte{}
	emptyKVal := []byte{0x11}
	zeroKCoexist := []byte{0x00}
	zeroKVal := []byte{0x22}
	emptyLeaf := vhashLeaf(emptyKCoexist, emptyKVal)
	zeroLeaf := vhashLeaf(zeroKCoexist, zeroKVal)
	// Empty has bit 8 = 1 (0xFF zone), so empty goes right.
	// {0x00} has bit 8 = 0 (0x00 padding byte), so {0x00} goes left.
	coexistRoot := vhashInner(8, zeroLeaf, emptyLeaf)

	g.comment("Empty key and {00} coexist: split at bit 8. Lookup empty: present (right child).")
	g.snap(coexistRoot)
	g.key(emptyKCoexist)
	g.val(emptyKVal)
	g.proof(buildConfirmProof([]pathStep{{8, zeroLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("Empty key and {00} coexist: lookup {00}: present (left child).")
	g.snap(coexistRoot)
	g.key(zeroKCoexist)
	g.val(zeroKVal)
	g.proof(buildConfirmProof([]pathStep{{8, emptyLeaf}}), true)
	g.verify(true)
	g.blank()

	// --- Three-key prefix chain ---
	// K={FF}, K0={FF,00}, K00={FF,00,00} all coexist.
	// K pads to:   FF 00 FF FF FF...
	// K0 pads to:  FF 00 00 FF FF...
	// K00 pads to: FF 00 00 00 FF FF...
	// All agree through byte 1 (00). At byte 2:
	//   K  = FF (0xFF zone), K0 = 00 (padding), K00 = 00 (actual) → K differs at bit 16.
	// K0 and K00 agree through byte 2 (00). At byte 3:
	//   K0 = FF (0xFF zone), K00 = 00 (padding) → differ at bit 24.
	// Tree: inner(16, inner(24, K00leaf, K0leaf), Kleaf)
	K3a := []byte{0xFF}
	K3aVal := []byte{0x11}
	K3b := []byte{0xFF, 0x00}
	K3bVal := []byte{0x22}
	K3c := []byte{0xFF, 0x00, 0x00}
	K3cVal := []byte{0x33}
	K3aLeaf := vhashLeaf(K3a, K3aVal)
	K3bLeaf := vhashLeaf(K3b, K3bVal)
	K3cLeaf := vhashLeaf(K3c, K3cVal)
	// K0 has bit 24 = 1 (0xFF zone), K00 has bit 24 = 0 (padding byte).
	K3inner := vhashInner(24, K3cLeaf, K3bLeaf)
	// K has bit 16 = 1 (0xFF zone), K0 and K00 have bit 16 = 0.
	K3root := vhashInner(16, K3inner, K3aLeaf)

	g.comment("Three-key prefix chain: K={FF}, K0={FF00}, K00={FF0000}. Lookup K: present.")
	g.snap(K3root)
	g.key(K3a)
	g.val(K3aVal)
	g.proof(buildConfirmProof([]pathStep{{16, K3inner}}), true)
	g.verify(true)
	g.blank()

	g.comment("Three-key prefix chain: lookup K0: present (two path steps).")
	g.snap(K3root)
	g.key(K3b)
	g.val(K3bVal)
	g.proof(buildConfirmProof([]pathStep{{24, K3cLeaf}, {16, K3aLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("Three-key prefix chain: lookup K00: present (two path steps).")
	g.snap(K3root)
	g.key(K3c)
	g.val(K3cVal)
	g.proof(buildConfirmProof([]pathStep{{24, K3bLeaf}, {16, K3aLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("Three-key prefix chain: lookup {FE}: absent (goes right with K at bit 16).")
	dpChain := buildDenyProof(K3a, K3aVal, []pathStep{{16, K3inner}})
	g.snap(K3root)
	g.key([]byte{0xFE})
	g.valAbsent()
	g.proof(dpChain, false)
	g.verify(true)
	g.blank()

	g.comment("Three-key prefix chain: lookup {FF01}: absent (goes left at bit 16, right at bit 24 with K0).")
	// {FF,01} pads to: FF 01 00 FF... At bit 16: byte 2 = 00 (padding) → 0 → left.
	// At bit 24: byte 3 = FF (0xFF zone) → 1 → right with K0.
	dpChain2 := buildDenyProof(K3b, K3bVal, []pathStep{{24, K3cLeaf}, {16, K3aLeaf}})
	g.snap(K3root)
	g.key([]byte{0xFF, 0x01})
	g.valAbsent()
	g.proof(dpChain2, false)
	g.verify(true)
	g.blank()

	// --- Wrong altkey across padding boundary ---
	// In the K/K0 coexist tree (split at bit 16), a deny proof
	// that claims altkey=K0 (left side) for a lookup key that goes right
	// must be rejected because the bit agreement check fails at bit 16.
	g.comment("Wrong altkey across padding boundary: lookup {FE} with altkey=K0 (wrong side), must reject.")
	// {FE} at bit 16: byte 2 = FF (0xFF zone) → 1 (right side, like K).
	// K0={FF,00} at bit 16: byte 2 = 00 (padding) → 0 (left side).
	// They disagree at bit 16 → reject.
	dpWrong := buildDenyProof(K0both, K0bothVal, []pathStep{{16, KbothLeaf}})
	g.snap(bothRoot)
	g.key([]byte{0xFE})
	g.valAbsent()
	g.proof(dpWrong, false)
	g.verify(false)
	g.blank()

	// --- 0xFF padding matching actual bytes ---
	// K={FF} pads to: FF 00 FF FF FF...
	// K'={FF,00,FF} pads to: FF 00 FF 00 FF FF...
	// They agree through byte 2 (K has 0xFF from padding zone,
	// K' has actual 0xFF). They differ at byte 3:
	//   K = FF (0xFF zone), K' = 00 (padding byte).
	// Split at bit 24: K' goes left (0), K goes right (1).
	KffPad := []byte{0xFF}
	KffPadVal := []byte{0xAA}
	KffActual := []byte{0xFF, 0x00, 0xFF}
	KffActualVal := []byte{0xBB}
	KffPadLeaf := vhashLeaf(KffPad, KffPadVal)
	KffActualLeaf := vhashLeaf(KffActual, KffActualVal)
	// K has bit 24 = 1 (0xFF zone), K' has bit 24 = 0 (padding).
	KffRoot := vhashInner(24, KffActualLeaf, KffPadLeaf)

	g.comment("0xFF padding matches actual bytes: K={FF} and K'={FF00FF} split at byte 3 (bit 24).")
	g.snap(KffRoot)
	g.key(KffPad)
	g.val(KffPadVal)
	g.proof(buildConfirmProof([]pathStep{{24, KffActualLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("0xFF padding matches actual bytes: K'={FF00FF} present (left child at bit 24).")
	g.snap(KffRoot)
	g.key(KffActual)
	g.val(KffActualVal)
	g.proof(buildConfirmProof([]pathStep{{24, KffPadLeaf}}), true)
	g.verify(true)
	g.blank()

	g.comment("0xFF padding matches actual bytes: lookup {FF00FF01}: absent (goes left at bit 24 with K').")
	// {FF,00,FF,01} pads to: FF 00 FF 01 00 FF...
	// At bit 24: byte 3 = 0x01 → bit 0 = 0 → left, same side as K' (bit 24 = 0 from padding).
	dpFF := buildDenyProof(KffActual, KffActualVal, []pathStep{{24, KffPadLeaf}})
	g.snap(KffRoot)
	g.key([]byte{0xFF, 0x00, 0xFF, 0x01})
	g.valAbsent()
	g.proof(dpFF, false)
	g.verify(true)
	g.blank()
}

func (g *gen) emptyKeyVal() {
	g.section("Empty key and empty value")

	// Single leaf with empty key.
	emptyK := []byte{}
	kval := []byte{0xAA, 0xBB}
	treeHash := vhashLeaf(emptyK, kval)

	g.comment("Empty key present in single-leaf tree.")
	g.snap(treeHash)
	g.key(emptyK)
	g.val(kval)
	g.proof(mpt.Proof{}, true)
	g.verify(true)
	g.blank()

	g.comment("Empty key stored. Lookup {00}: absent (different key).")
	dpK0 := buildDenyProof(emptyK, kval, nil)
	g.snap(treeHash)
	g.key([]byte{0x00})
	g.valAbsent()
	g.proof(dpK0, false)
	g.verify(true)
	g.blank()

	g.comment("Empty key stored. Existence proof must NOT verify {00} as present.")
	g.snap(treeHash)
	g.key([]byte{0x00})
	g.val(kval)
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// {00} stored, lookup empty key.
	zeroKey := []byte{0x00}
	zeroVal := []byte{0xCC}
	treeHash2 := vhashLeaf(zeroKey, zeroVal)

	g.comment("{00} stored. Lookup empty key: absent (different key).")
	dpEmpty := buildDenyProof(zeroKey, zeroVal, nil)
	g.snap(treeHash2)
	g.key(emptyK)
	g.valAbsent()
	g.proof(dpEmpty, false)
	g.verify(true)
	g.blank()

	g.comment("{00} stored. Existence proof must NOT verify empty key as present.")
	g.snap(treeHash2)
	g.key(emptyK)
	g.val(zeroVal)
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// Key present with empty value.
	someKey := []byte{0xCC}
	emptyV := []byte{}
	treeHash3 := vhashLeaf(someKey, emptyV)

	g.comment("Key present with empty value.")
	g.snap(treeHash3)
	g.key(someKey)
	g.val(emptyV)
	g.proof(mpt.Proof{}, true)
	g.verify(true)
	g.blank()

	// Both key and val empty.
	treeHash4 := vhashLeaf(emptyK, emptyV)
	g.comment("Both key and value are empty.")
	g.snap(treeHash4)
	g.key(emptyK)
	g.val(emptyV)
	g.proof(mpt.Proof{}, true)
	g.verify(true)
	g.blank()

	// Two-leaf tree with empty key.
	// With 0x00+0xFF padding, empty key pads to 00 FF FF...,
	// and {0x80} has bit 0 = 1 (actual byte).
	// Empty key bit 0 = 0 (0x00 padding), so empty goes left.
	// {0x80} bit 0 = 1, so {0x80} goes right.
	emptyKval2 := []byte{0x11}
	other := []byte{0x80}
	otherVal := []byte{0x22}
	lh := vhashLeaf(emptyK, emptyKval2)
	rh := vhashLeaf(other, otherVal)
	root := vhashInner(0, lh, rh)

	g.comment("Two-leaf tree: empty key on left, {80} on right. Lookup empty key: present.")
	g.snap(root)
	g.key(emptyK)
	g.val(emptyKval2)
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(true)
	g.blank()

	g.comment("Two-leaf tree: empty key on left. Lookup {01}: absent (bit 0 = 0, same side as empty).")
	dpK0tree := buildDenyProof(emptyK, emptyKval2, []pathStep{{0, rh}})
	g.snap(root)
	g.key([]byte{0x01})
	g.valAbsent()
	g.proof(dpK0tree, false)
	g.verify(true)
	g.blank()
}

func (g *gen) proofStructure() {
	g.section("Proof structure and hash integrity")

	// --- Key/val boundary confusion ---
	// If the leaf hash doesn't include key and val lengths, then
	// key=AB,val=CD and key=A,val=BCD would collide.
	k1 := []byte{0xAA, 0xBB}
	v1 := []byte{0xCC}
	th := vhashLeaf(k1, v1)

	g.comment("Key/val boundary confusion: key={AABB} val={CC} must NOT verify key={AA} val={BBCC}.")
	g.snap(th)
	g.key([]byte{0xAA})
	g.val([]byte{0xBB, 0xCC})
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	g.comment("Key/val boundary confusion: key={AABB} val={CC} must NOT verify key={AABBCC} val={}.")
	g.snap(th)
	g.key([]byte{0xAA, 0xBB, 0xCC})
	g.val([]byte{})
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	g.comment("Key/val boundary confusion: key={AABB} val={CC} must NOT verify key={} val={AABBCC}.")
	g.snap(th)
	g.key([]byte{})
	g.val([]byte{0xAA, 0xBB, 0xCC})
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// --- Swapped key and val ---
	g.comment("Swapped key and val of equal length: key={AA} val={BB} must NOT verify key={BB} val={AA}.")
	k2 := []byte{0xAA}
	v2 := []byte{0xBB}
	th2 := vhashLeaf(k2, v2)
	g.snap(th2)
	g.key(v2) // swapped
	g.val(k2) // swapped
	g.proof(mpt.Proof{}, true)
	g.verify(false)
	g.blank()

	// --- Non-empty proof for empty tree ---
	emptyHash := sha256.Sum256(nil)
	fakeProof := buildDenyProof([]byte{0xFF}, []byte{0xAA}, nil)

	g.comment("Non-empty proof for empty tree (absent claim): must reject.")
	g.snap(mpt.Hash(emptyHash))
	g.key([]byte{0x42})
	g.valAbsent()
	g.rawProof(fakeProof)
	g.verify(false)
	g.blank()

	// --- Proof steps at various bit positions with wrong hash ---
	// These steps are structurally valid but produce wrong hashes.
	shortK := []byte{0xFF}
	shortV := []byte{0x42}
	shortHash := vhashLeaf(shortK, shortV)
	lookupK := []byte{0xFE}
	sib := sha256.Sum256([]byte("sibling"))

	g.comment("Proof step at bit 9 for 1-byte keys: wrong hash, must reject.")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(buildDenyProof(shortK, shortV, []pathStep{{9, mpt.Hash(sib)}}))
	g.verify(false)
	g.blank()

	g.comment("Proof step at bit 8 for 1-byte keys: wrong hash, must reject.")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(buildDenyProof(shortK, shortV, []pathStep{{8, mpt.Hash(sib)}}))
	g.verify(false)
	g.blank()

	g.comment("Proof step at bit 7 for 1-byte keys: wrong hash, must reject.")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(buildDenyProof(shortK, shortV, []pathStep{{7, mpt.Hash(sib)}}))
	g.verify(false)
	g.blank()

	// --- Non-decreasing bit positions ---
	sib1 := sha256.Sum256([]byte("sib1"))
	sib2 := sha256.Sum256([]byte("sib2"))

	g.comment("Equal bit positions in proof (bit 5, bit 5): must reject.")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(buildDenyProof(shortK, shortV, []pathStep{{5, mpt.Hash(sib1)}, {5, mpt.Hash(sib2)}}))
	g.verify(false)
	g.blank()

	g.comment("Increasing bit positions in proof (bit 3, bit 5): must reject.")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(buildDenyProof(shortK, shortV, []pathStep{{3, mpt.Hash(sib1)}, {5, mpt.Hash(sib2)}}))
	g.verify(false)
	g.blank()

	// --- Invalid varint ---
	g.comment("Invalid varint in proof: unterminated continuation byte (0x80).")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof([]byte{0x80})
	g.verify(false)
	g.blank()

	g.comment("Invalid varint: five continuation bytes (overlong encoding).")
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof([]byte{0x80, 0x80, 0x80, 0x80, 0x80})
	g.verify(false)
	g.blank()

	// --- Proof with huge varint for altkey length ---
	g.comment("Huge varint for altkey length: must reject (not enough data).")
	var hugeProof []byte
	hugeProof = binary.AppendUvarint(hugeProof, 1<<32)
	g.snap(shortHash)
	g.key(lookupK)
	g.valAbsent()
	g.rawProof(hugeProof)
	g.verify(false)
	g.blank()

	// --- Altkey/altval swapped in non-existence proof ---
	// If the proof has altkey and altval swapped (same total bytes),
	// the leaf hash will differ and the proof should fail.
	swappedKey := []byte{0x11, 0x22}
	swappedVal := []byte{0x33, 0x44}
	swappedHash := vhashLeaf(swappedKey, swappedVal)

	g.comment("Swapped altkey/altval in deny proof: must reject.")
	g.snap(swappedHash)
	g.key([]byte{0x11, 0x23}) // different from swappedKey
	g.valAbsent()
	// Build proof with altkey and altval swapped
	g.proof(buildDenyProof(swappedVal, swappedKey, nil), false)
	g.verify(false)
	g.blank()

	// --- Existence proof reuse: proof for key K should not verify key K2 ---
	// Two-leaf tree: K on left, K2 on right. Existence proof for K
	// contains sibling hash. Using same proof with K2 should fail.
	kLeft := []byte{0x10}
	vLeft := []byte{0xAA}
	kRight := []byte{0x90}
	vRight := []byte{0xBB}
	lh := vhashLeaf(kLeft, vLeft)
	rh := vhashLeaf(kRight, vRight)
	root := vhashInner(0, lh, rh)

	g.comment("Existence proof for K={10} must NOT verify K2={11} (different key, same side).")
	g.snap(root)
	g.key([]byte{0x11}) // same side as kLeft (bit 0 = 0)
	g.val(vLeft)
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(false)
	g.blank()

	g.comment("Existence proof for K={10} must NOT verify K2={90} (different key, other side).")
	g.snap(root)
	g.key(kRight)
	g.val(vLeft) // right key but left val
	g.proof(buildConfirmProof([]pathStep{{0, rh}}), true)
	g.verify(false)
	g.blank()

	// --- Cross-proof reuse: deny proof should not verify as existence ---
	// A non-existence proof for key M contains altkey K and altval V.
	// If someone strips the altkey/altval prefix and tries to use the
	// path steps as an existence proof, it should fail.
	g.comment("Path steps from deny proof reused as existence proof: must reject.")
	// Extract just the path steps from what would be a deny proof.
	pathOnly := buildConfirmProof([]pathStep{{0, rh}})
	// Use kLeft and vLeft as if present — hashLeafVar(kLeft,vLeft) = lh,
	// and the path step hashes to root. So this SHOULD verify...
	// unless the proof is for a different key.
	// Actually this is valid! kLeft IS in the tree. Let me use a different key.
	g.snap(root)
	g.key([]byte{0x30}) // not in tree, same side as kLeft
	g.val(vLeft)
	g.proof(pathOnly, true)
	g.verify(false)
	g.blank()
}
