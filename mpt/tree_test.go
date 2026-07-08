// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

var goldenTrees = []struct {
	keys []Key
	hash Hash
}{
	{
		[]Key{},
		// sha256 /dev/null
		sha(),
	},
	{
		[]Key{h("0...0")},
		sha("\x00\x20", h("00...0"), "\x20", h("420...0")),
	},
	{
		[]Key{h("80...0")},
		sha("\x00\x20", h("80...0"), "\x20", h("420...0")),
	},
	{
		[]Key{h("0...0"), h("80...0")},
		sha(
			"\x01\x00",
			sha("\x00\x20", h("00...0"), "\x20", h("420...0")),
			sha("\x00\x20", h("80...0"), "\x20", h("420...01")),
		),
	},
	{
		[]Key{h("0...0"), h("0010...0")},
		sha(
			"\x01\x0b",
			sha("\x00\x20", h("0...0"), "\x20", h("420...0")),
			sha("\x00\x20", h("0010...0"), "\x20", h("420...01")),
		),
	},
	{
		[]Key{h("0...0"), h("0010...0"), h("80...0")},
		sha(
			"\x01\x00",
			sha(
				"\x01\x0b",
				sha("\x00\x20", h("0...0"), "\x20", h("420...0")),
				sha("\x00\x20", h("0010...0"), "\x20", h("420...01")),
			),
			sha("\x00\x20", h("80...0"), "\x20", h("420...02")),
		),
	},
}

var missing = []Key{
	h("02...2"),
	h("22...2"),
	h("42...2"),
	h("62...2"),
	h("82...2"),
	h("a2...2"),
	h("c2...2"),
	h("e2...2"),
	h("f2...2"),
}

func testImpls(t *testing.T, run func(*testing.T, func(*testing.T) *testTree)) {
	t.Run("impl=mem", func(t *testing.T) { run(t, testMemTree) })
	t.Run("impl=disk", func(t *testing.T) { run(t, testDiskTree) })
}

func TestGoldenTrees(t *testing.T) {
	testImpls(t, func(t *testing.T, newTree func(*testing.T) *testTree) {
		for i, tree := range goldenTrees {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				tt := newTree(t)
				defer tt.tree.Close()
				e := int64(1)
				if len(tree.keys) == 0 {
					e = 0
				}
				for i, k := range tree.keys {
					tt.set(k, v(i))
				}
				tt.snap(e, tree.hash)
				for i, k := range tree.keys {
					tt.get(k, v(i), true)
				}
				for _, k := range missing {
					tt.get(k, Val{}, false)
				}
			})
		}
	})
}

func TestAllTrees(t *testing.T) {
	testImpls(t, func(t *testing.T, newTree func(*testing.T) *testTree) {
		for _, keys := range []string{"hi", "lo"} {
			t.Run(keys, func(t *testing.T) {
				const B = 3
				const N = 1 << B
				k := func(i int) Key {
					k := make(Key, 32)
					if keys == "hi" {
						k[0] = byte(i) << (8 - B)
					} else {
						k[len(k)-1] = byte(i)
					}
					return k
				}
				for leaves := range 1 << N {
					tt := newTree(t)
					var kvs []KeyVal
					for i := range N {
						if leaves&(1<<i) != 0 {
							kvs = append(kvs, KeyVal{k(i), v(i)})
						}
					}
					for _, i := range rand.Perm(len(kvs)) {
						tt.set(kvs[i].Key, kvs[i].Val)
					}

					e := 1
					if len(kvs) == 0 {
						e = 0
					}
					for round := range 3 {
						tt.snap(int64(e*(1+round)), TreeHash(slices.Values(kvs)))
						for i := range N {
							if leaves&(1<<i) != 0 {
								tt.get(k(i), v(i+N*round), true)
							} else {
								tt.get(k(i), Val{}, false)
							}
						}
						kvs = kvs[:0]
						for i := range N {
							if leaves&(1<<i) != 0 {
								val := v(i + N*(round+1))
								tt.set(k(i), val)
								kvs = append(kvs, KeyVal{k(i), val})
							}
						}
					}
					tt.tree.Close()
				}
			})
		}
	})
}

func TestPredictRandom(t *testing.T) {
	testImpls(t, func(t *testing.T, newTree func(*testing.T) *testTree) {
		const N = 50
		for iter := range 10 {
			t.Run(fmt.Sprint(iter), func(t *testing.T) {
				tt := newTree(t)
				defer tt.tree.Close()

				// Build random tree.
				var init []KeyVal
				for i := range N {
					s := sha(fmt.Sprintf("key-%d-%d", iter, i))
					init = append(init, KeyVal{s[:], v(i)})
				}
				for _, kv := range init {
					tt.set(kv.Key, kv.Val)
				}
				tt.tree.Snap(1)

				// Choose random edits, using map to dedup keys.
				update := make(map[string]Val)
				for i := range 10 {
					var k Key
					if i%2 == 0 {
						// Edit existing
						k = init[rand.N(N)].Key
					} else {
						// New key
						s := sha(fmt.Sprintf("newkey-%d-%d", iter, i))
						k = s[:]
					}
					s := sha(fmt.Sprintf("val-%d-%d", iter, i))
					update[string(k)] = s[:]
				}

				// Sort edits.
				var edits []KeyVal
				for ks, val := range update {
					edits = append(edits, KeyVal{Key(ks), val})
				}
				slices.SortFunc(edits, KeyVal.Compare)

				// Predict.
				hash, err := tt.tree.Predict(edits)
				if err != nil {
					t.Fatal(err)
				}

				// Check against applying to tree.
				for _, kv := range edits {
					tt.set(kv.Key, kv.Val)
				}
				want, err := tt.tree.Snap(2)
				if err != nil {
					t.Fatal(err)
				}

				if hash != want.Hash {
					t.Fatalf("Iter %d: Predict = %v, want %v", iter, hash, want.Hash)
				}
			})
		}
	})
}

func h(x string) []byte {
	if l, r, ok := strings.Cut(x, "..."); ok && l != "" && r != "" && l[len(l)-1] == r[0] {
		x = l + strings.Repeat(r[0:1], 64-len(l)-len(r)) + r
	}
	h, err := hex.DecodeString(x)
	if err != nil || len(h) != 32 {
		panic("bad hex: " + x)
	}
	return h
}

func v(i int) Val {
	return h(fmt.Sprintf("42%062x", i))
}

func enc(list ...any) []byte {
	var out []byte
	for _, item := range list {
		switch item := item.(type) {
		default:
			panic(fmt.Sprintf("enc %T", item))
		case string:
			out = append(out, item...)
		case []byte:
			out = append(out, item...)
		case [32]byte:
			out = append(out, item[:]...)
		case Key:
			out = append(out, item...)
		case Val:
			out = append(out, item...)
		case Hash:
			out = append(out, item[:]...)
		}
	}
	return out
}

func sha(list ...any) [32]byte {
	return sha256.Sum256(enc(list...))
}

type testTree struct {
	t    *testing.T
	tree Tree
	log  bytes.Buffer
}

func testMemTree(t *testing.T) *testTree {
	return &testTree{t: t, tree: NewMemTree()}
}

// DevNull returns a file like the Unix /dev/null: it can be written but is always empty.
// Passing two DevNull files to New creates a Mem with no on-disk backing.
func DevNull() File {
	return new(devNull)
}

type devNull struct{}

func (*devNull) ReadAt(b []byte, off int64) (int, error)  { return 0, io.EOF }
func (*devNull) WriteAt(b []byte, off int64) (int, error) { return len(b), nil }

func (*devNull) Close() error { return nil }
func (*devNull) Sync() error  { return nil }

func newDiskTree() Tree {
	t, err := New(DevNull(), DevNull(), new(memFile))
	if err != nil {
		panic(err)
	}
	return t
}

func testDiskTree(t *testing.T) *testTree {
	return &testTree{t: t, tree: newDiskTree()}
}

func (tt *testTree) set(key Key, val Val) {
	err := tt.tree.Set(key, val)
	if err != nil {
		tt.t.Fatalf("Set %v: %v\n\nLog:\n%s", key, err, &tt.log)
	}
	fmt.Fprintf(&tt.log, "set(%v, %v)\n", key, val)
}

func (tt *testTree) snap(version int64, hash Hash) {
	tt.t.Helper()
	snap, err := tt.tree.Snap(version)
	if err != nil {
		tt.t.Fatalf("Tree.Snap: %v\n\nLog:\n%s", err, &tt.log)
	}
	if snap.Version != version || snap.Hash != hash {
		tt.t.Fatalf("Tree.Snap = %d, %v, want %d, %v\n\nLog:\n%s",
			snap.Version, snap.Hash, version, hash, &tt.log)
	}
	fmt.Fprintf(&tt.log, "snap(%d) = %v\n", version, hash)
}

func (tt *testTree) get(key Key, val Val, ok bool) {
	tt.t.Helper()

	defer func() {
		if r := recover(); r != nil {
			tt.t.Fatalf("panic: %v\n\nLog:\n%s\n%s", r, &tt.log, debug.Stack())
		}
	}()

	snap, err := tt.tree.Snap(1)
	if err != nil {
		tt.t.Fatalf("Tree.Snap: %v\n\nLog:\n%s", err, &tt.log)
	}

	v, o, proof, err := tt.tree.Prove(key)
	if err != nil {
		tt.t.Fatalf("Tree.Prove: %v\n\nLog:\n%s", err, &tt.log)
	}
	var vb []byte
	if o {
		vb = []byte(v)
	}
	err = Verify(snap, []byte(key), vb, o, proof)
	if err != nil {
		tt.t.Fatalf("Verify %v: %v\nSnap: %v\nProof: %x\n\nLog:\n%s", key, err, snap, proof, &tt.log)
	}
	if !bytes.Equal([]byte(v), []byte(val)) || o != ok {
		tt.t.Fatalf("get %v:\nhave %v, %v\nwant %v, %v\n\nLog:\n%s", key, v, o, val, ok, &tt.log)
	}

	//fmt.Fprintf(&tt.log, "get(%v)\n", key)
}

func BenchmarkSet1K_100K(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkSet(b, NewMemTree(), 1000, 100e3) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkSet(b, newDiskTree(), 1000, 100e3) })
}

func BenchmarkSet1K_1M(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkSet(b, NewMemTree(), 1000, 1e6) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkSet(b, newDiskTree(), 1000, 1e6) })
}

func BenchmarkSet1K_10M(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkSet(b, NewMemTree(), 1000, 10e6) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkSet(b, newDiskTree(), 1000, 10e6) })
}

func benchmarkSet(b *testing.B, tree Tree, n, treeSize int) {
	var todo [][2]Hash
	for i := range n {
		todo = append(todo, [2]Hash{sha(v(i)), Hash(v(i))})
	}
	for i := range treeSize {
		s := sha("old", v(i))
		tree.Set(s[:], v(i))
	}
	tree.Snap(1)

	b.ReportAllocs()
	for b.Loop() {
		//	tree1 := *tree
		for _, kv := range todo {
			tree.Set(kv[0][:], kv[1][:])
		}
		tree.Snap(2)
	}
}

func BenchmarkProofIn100K(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkProof(b, NewMemTree(), 100e3) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkProof(b, newDiskTree(), 100e3) })
}

func BenchmarkProofIn1M(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkProof(b, NewMemTree(), 1e6) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkProof(b, newDiskTree(), 1e6) })
}

func BenchmarkProofIn10M(b *testing.B) {
	b.Run("impl=mem", func(b *testing.B) { benchmarkProof(b, NewMemTree(), 10e6) })
	b.Run("impl=disk", func(b *testing.B) { benchmarkProof(b, newDiskTree(), 10e6) })
}

func benchmarkProof(b *testing.B, tree Tree, treeSize int) {
	for i := range treeSize {
		s := sha("old", v(i))
		tree.Set(s[:], v(i))
	}
	tree.Snap(1)
	s := sha("old", v(0))
	key := Key(s[:])

	b.ReportAllocs()
	for b.Loop() {
		_, _, _, err := tree.Prove(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestPredict(t *testing.T) {
	testImpls(t, func(t *testing.T, newTree func(*testing.T) *testTree) {
		tt := newTree(t)
		defer tt.tree.Close()
		tt.set(h("0...0"), v(1))
		tt.set(h("40...0"), v(2))
		tt.set(h("80...0"), v(3))
		tt.tree.Snap(1)

		hash, err := tt.tree.Predict([]KeyVal{
			{Key: h("20...0"), Val: v(4)},
			{Key: h("40...0"), Val: v(5)},
		})
		if err != nil {
			t.Fatal(err)
		}

		want := TreeHash(slices.Values([]KeyVal{
			{h("0...0"), v(1)},
			{h("20...0"), v(4)},
			{h("40...0"), v(5)},
			{h("80...0"), v(3)},
		}))

		if hash != want {
			t.Errorf("Predict = %v, want %v", hash, want)
		}

		_, err = tt.tree.Predict([]KeyVal{
			{Key: h("20...0"), Val: v(4)},
			{Key: h("20...0"), Val: v(5)},
		})
		if err != ErrInvalidPredict {
			t.Errorf("Predict with duplicate keys: %v, want ErrInvalidPredict", err)
		}

		_, err = tt.tree.Predict([]KeyVal{
			{Key: h("40...0"), Val: v(4)},
			{Key: h("20...0"), Val: v(5)},
		})
		if err != ErrInvalidPredict {
			t.Errorf("Predict with inverted keys: %v, want ErrInvalidPredict", err)
		}

	})
}

func TestVerify(t *testing.T) {
	file := "testdata/verify.txt"
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var (
		snap     Hash
		key, val []byte
		ok       bool
		proof    Proof
	)
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// Join continuation lines (trailing backslash).
		for strings.HasSuffix(line, "\\") {
			line = line[:len(line)-1]
			i++
			if i < len(lines) {
				line += lines[i]
			}
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cmd, arg, _ := strings.Cut(line, " ")
		arg = strings.TrimSpace(arg)

		switch cmd {
		case "snap":
			b := decodeHex(t, file, i+1, arg)
			if len(b) != 32 {
				t.Fatalf("line %d: snap must be 32 bytes, got %d", i+1, len(b))
			}
			snap = Hash(b)
		case "key":
			key = decodeHex(t, file, i+1, arg)
		case "val":
			if arg == "-" {
				val = nil
				ok = false
			} else {
				val = decodeHex(t, file, i+1, arg)
				ok = true
			}
		case "proof":
			proof = Proof(decodeHex(t, file, i+1, arg))
		case "verify":
			want := arg == "true"
			result := Verify(Snapshot{Version: 1, Hash: snap}, key, val, ok, proof)
			if want && result != nil {
				t.Errorf("%s:%d: Verify should succeed but got: %v", file, i+1, result)
			} else if !want && result == nil {
				t.Errorf("%s:%d: Verify should fail but succeeded", file, i+1)
			}
		default:
			t.Fatalf("%s:%d: unknown directive %q", file, i+1, cmd)
		}
	}
}

func decodeHex(t *testing.T, file string, lineno int, s string) []byte {
	t.Helper()
	if s == "''" {
		return nil
	}
	// Remove spaces and tabs from hex string.
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s:%d: bad hex %q: %v", file, lineno, s, err)
	}
	return b
}

type treeHashTest struct {
	line int
	kvs  []KeyVal
	hash Hash
}

func parseTreeHashTests(t *testing.T) []treeHashTest {
	t.Helper()
	file := "testdata/treehash.txt"
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var tests []treeHashTest
	var kvs []KeyVal
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cmd, arg, _ := strings.Cut(line, " ")
		arg = strings.TrimSpace(arg)

		switch cmd {
		case "kv":
			parts := strings.Fields(arg)
			if len(parts) != 2 {
				t.Fatalf("%s:%d: kv needs 2 args", file, i+1)
			}
			key := decodeHex(t, file, i+1, parts[0])
			val := decodeHex(t, file, i+1, parts[1])
			kvs = append(kvs, KeyVal{Key: key, Val: val})
		case "hash":
			want := decodeHex(t, file, i+1, arg)
			if len(want) != 32 {
				t.Fatalf("%s:%d: hash must be 32 bytes", file, i+1)
			}
			tests = append(tests, treeHashTest{
				line: i + 1,
				kvs:  slices.Clone(kvs),
				hash: Hash(want),
			})
			kvs = kvs[:0]
		default:
			t.Fatalf("%s:%d: unknown directive %q", file, i+1, cmd)
		}
	}
	return tests
}

func TestTreeHash(t *testing.T) {
	tests := parseTreeHashTests(t)
	for _, tc := range tests {
		kvs := slices.Clone(tc.kvs)
		slices.SortFunc(kvs, KeyVal.Compare)
		got := TreeHash(slices.Values(kvs))
		if got != tc.hash {
			t.Errorf("testdata/treehash.txt:%d: TreeHash = %x, want %x", tc.line, got, tc.hash)
		}
	}
}

func TestTreeImpls(t *testing.T) {
	orders := []struct {
		name string
		fn   func([]KeyVal) []KeyVal
	}{
		{"file_order", func(kvs []KeyVal) []KeyVal {
			return slices.Clone(kvs)
		}},
		{"file_order_reverse", func(kvs []KeyVal) []KeyVal {
			k := slices.Clone(kvs)
			slices.Reverse(k)
			return k
		}},
		{"key_compare_order", func(kvs []KeyVal) []KeyVal {
			k := slices.Clone(kvs)
			slices.SortFunc(k, KeyVal.Compare)
			return k
		}},
		{"key_compare_order_reverse", func(kvs []KeyVal) []KeyVal {
			k := slices.Clone(kvs)
			slices.SortFunc(k, KeyVal.Compare)
			slices.Reverse(k)
			return k
		}},
		{"shuffled", func(kvs []KeyVal) []KeyVal {
			k := slices.Clone(kvs)
			rand.Shuffle(len(k), func(i, j int) { k[i], k[j] = k[j], k[i] })
			return k
		}},
	}

	tests := parseTreeHashTests(t)
	testImpls(t, func(t *testing.T, newTree func(*testing.T) *testTree) {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("line%d", tc.line), func(t *testing.T) {
				for _, ord := range orders {
					t.Run(ord.name, func(t *testing.T) {
						t.Parallel()
						kvs := ord.fn(tc.kvs)
						for n := 0; n <= len(kvs); n += 1 + len(kvs)/10 {
							func() {
								tt := newTree(t)
								defer tt.tree.Close()

								for _, kv := range kvs[:n] {
									tt.set(kv.Key, kv.Val)
								}
								e1 := int64(1)
								if n == 0 {
									e1 = 0
								}
								if _, err := tt.tree.Snap(e1); err != nil {
									t.Fatalf("Snap(%d): %v", e1, err)
								}

								rem := slices.Clone(kvs[n:])
								slices.SortFunc(rem, KeyVal.Compare)
								predictedHash, err := tt.tree.Predict(rem)
								if err != nil {
									t.Fatalf("Predict: %v", err)
								}

								for _, kv := range kvs[n:] {
									tt.set(kv.Key, kv.Val)
								}
								e2 := int64(2)
								if len(tc.kvs) == 0 {
									e2 = 0
								}
								tt.snap(e2, tc.hash)
								if predictedHash != tc.hash {
									t.Errorf("n=%d Predict = %v, want %v", n, predictedHash, tc.hash)
								}
								for _, kv := range tc.kvs {
									tt.get(kv.Key, kv.Val, true)
								}
							}()
						}
					})
				}
			})
		}
	})
}
