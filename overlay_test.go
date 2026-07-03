package torchwood_test

import (
	"fmt"
	"slices"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// TestHashReaderOverlayRightEdge checks that appending records, computing tree
// and subtree hashes, and proving new records only need the right edge of the
// original tree.
func TestHashReaderOverlayRightEdge(t *testing.T) {
	const N = 130
	leaves, full := buildTree(t, N)
	for n0 := int64(0); n0 <= N; n0++ {
		edge := make(map[int64]tlog.Hash)
		if n0 > 0 {
			idx := torchwood.RightEdge(n0)
			hashes, err := full.ReadHashes(idx)
			fatalIfErr(t, err)
			for i, id := range idx {
				edge[id] = hashes[i]
			}
		}
		r := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
			list := make([]tlog.Hash, 0, len(indexes))
			for _, id := range indexes {
				h, ok := edge[id]
				if !ok {
					return nil, fmt.Errorf("index %d not on the right edge of tree of size %d", id, n0)
				}
				list = append(list, h)
			}
			return list, nil
		})

		overlay := torchwood.NewHashReaderOverlay(n0, r)
		for n := n0; n < N; n++ {
			if overlay.Size() != n {
				t.Fatalf("n0=%d: Size() = %d, want %d", n0, overlay.Size(), n)
			}
			fatalIfErr(t, overlay.AppendRecordHash(leaves[n]))

			got, err := tlog.TreeHash(n+1, overlay)
			fatalIfErr(t, err)
			want, err := tlog.TreeHash(n+1, full)
			fatalIfErr(t, err)
			if got != want {
				t.Fatalf("n0=%d: TreeHash(%d) = %v, want %v", n0, n+1, got, want)
			}
		}

		th, err := tlog.TreeHash(N, overlay)
		fatalIfErr(t, err)
		for i := n0; i < N; i++ {
			proof, err := tlog.ProveRecord(N, i, overlay)
			fatalIfErr(t, err)
			if err := tlog.CheckRecord(proof, N, th, i, leaves[i]); err != nil {
				t.Fatalf("n0=%d: CheckRecord(%d): %v", n0, i, err)
			}
		}

		for start := int64(0); start < N; start++ {
			// Subtrees wholly within the original tree may not be on its
			// right edge, so only check those extending past it.
			for end := max(start+1, n0+1); end <= N; end++ {
				if !torchwood.ValidSubtree(start, end) {
					continue
				}
				got, err := torchwood.SubtreeHash(start, end, overlay)
				fatalIfErr(t, err)
				want, err := torchwood.SubtreeHash(start, end, full)
				fatalIfErr(t, err)
				if got != want {
					t.Fatalf("n0=%d: SubtreeHash(%d, %d) = %v, want %v", n0, start, end, got, want)
				}
			}
		}
	}
}

// TestHashReaderOverlayFullTree checks subtree hashes and tile contents
// against a reader for the whole tree, with the underlying reader restricted
// to the original tree.
func TestHashReaderOverlayFullTree(t *testing.T) {
	const N = 130
	leaves, full := buildTree(t, N)
	for n0 := int64(0); n0 <= N; n0++ {
		base := tlog.StoredHashCount(n0)
		r := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
			for _, id := range indexes {
				if id >= base {
					return nil, fmt.Errorf("index %d beyond the original tree of size %d", id, n0)
				}
			}
			return full.ReadHashes(indexes)
		})

		overlay := torchwood.NewHashReaderOverlay(n0, r)
		for n := n0; n < N; n++ {
			fatalIfErr(t, overlay.AppendRecordHash(leaves[n]))
		}

		for start := int64(0); start < N; start++ {
			for end := start + 1; end <= N; end++ {
				if !torchwood.ValidSubtree(start, end) {
					continue
				}
				got, err := torchwood.SubtreeHash(start, end, overlay)
				fatalIfErr(t, err)
				want, err := torchwood.SubtreeHash(start, end, full)
				fatalIfErr(t, err)
				if got != want {
					t.Fatalf("n0=%d: SubtreeHash(%d, %d) = %v, want %v", n0, start, end, got, want)
				}
			}
		}

		for _, tile := range tlog.NewTiles(2, n0, N) {
			got, err := tlog.ReadTileData(tile, overlay)
			fatalIfErr(t, err)
			want, err := tlog.ReadTileData(tile, full)
			fatalIfErr(t, err)
			if !slices.Equal(got, want) {
				t.Fatalf("n0=%d: ReadTileData(%v) = %x, want %x", n0, tile, got, want)
			}
		}
	}
}

func TestHashReaderOverlayBatchedReads(t *testing.T) {
	const n0 = 100
	leaves, full := buildTree(t, 130)
	var reads int
	r := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		reads++
		return full.ReadHashes(indexes)
	})
	overlay := torchwood.NewHashReaderOverlay(n0, r)
	for n := int64(n0); n < 130; n++ {
		fatalIfErr(t, overlay.AppendRecordHash(leaves[n]))
	}

	// Interleave original tree and overlay indexes.
	base := tlog.StoredHashCount(n0)
	indexes := []int64{0, base, 1, base + 1, 2, base + 2, 3}
	reads = 0
	got, err := overlay.ReadHashes(indexes)
	fatalIfErr(t, err)
	if reads != 1 {
		t.Errorf("ReadHashes made %d underlying reads, want 1", reads)
	}
	want, err := full.ReadHashes(indexes)
	fatalIfErr(t, err)
	if !slices.Equal(got, want) {
		t.Errorf("ReadHashes(%v) = %v, want %v", indexes, got, want)
	}
}

func TestHashReaderOverlayErrors(t *testing.T) {
	leaves, full := buildTree(t, 10)

	// Requests beyond the extended tree are rejected.
	overlay := torchwood.NewHashReaderOverlay(10, full)
	if _, err := overlay.ReadHashes([]int64{tlog.StoredHashCount(10)}); err == nil {
		t.Errorf("expected error for index beyond the tree size")
	}
	if _, err := overlay.ReadHashes([]int64{-1}); err == nil {
		t.Errorf("expected error for negative index")
	}

	// A nil underlying reader works from size 0...
	overlay = torchwood.NewHashReaderOverlay(0, nil)
	for n := int64(0); n < 10; n++ {
		fatalIfErr(t, overlay.AppendRecordHash(leaves[n]))
	}
	got, err := tlog.TreeHash(10, overlay)
	fatalIfErr(t, err)
	want, err := tlog.TreeHash(10, full)
	fatalIfErr(t, err)
	if got != want {
		t.Errorf("TreeHash(10) = %v, want %v", got, want)
	}

	// ...but fails requests for a non-empty original tree.
	overlay = torchwood.NewHashReaderOverlay(10, nil)
	if _, err := tlog.TreeHash(10, overlay); err == nil {
		t.Errorf("expected error for nil underlying reader")
	}
	// Record 10 completes no subtrees, so it doesn't need the original tree.
	fatalIfErr(t, overlay.AppendRecordHash(leaves[0]))
	// Record 11 completes the subtree [10, 12) and needs the hash of [8, 10).
	if err := overlay.AppendRecordHash(leaves[1]); err == nil {
		t.Errorf("expected error appending a record that completes a subtree")
	}
	if overlay.Size() != 11 {
		t.Errorf("Size() = %d, want 11 after the failed append", overlay.Size())
	}
}
