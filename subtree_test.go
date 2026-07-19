package torchwood_test

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"slices"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

func TestAccumulatedSubtreeProof(t *testing.T) {
	o := sha256.New()
	_, tree := buildTree(t, 130)
	for n := int64(0); n <= 130; n++ {
		th, err := tlog.TreeHash(n, tree)
		fatalIfErr(t, err)
		for end := int64(0); end <= n; end++ {
			for start := int64(0); start <= end; start++ {
				if !torchwood.ValidSubtree(start, end) {
					continue
				}
				sh, err := torchwood.SubtreeHash(start, end, tree)
				fatalIfErr(t, err)

				p, err := torchwood.ProveSubtree(n, start, end, tree)
				fatalIfErr(t, err)

				fmt.Fprintf(o, "[%d, %d) %d", start, end, n)
				for _, h := range p {
					fmt.Fprintf(o, " %x", h[:])
				}
				fmt.Fprintln(o)

				err = torchwood.CheckSubtree(p, n, th, start, end, sh)
				fatalIfErr(t, err)

				err = torchwood.CheckSubtree(p, n, th, start, end, flip(sh))
				if err == nil {
					t.Errorf("CheckSubtree accepted wrong sh for [%d, %d) in tree of size %d", start, end, n)
				}

				err = torchwood.CheckSubtree(p, n, flip(th), start, end, sh)
				if start == end {
					// An empty subtree is contained in every tree,
					// so the tree hash is not checked.
					if err != nil {
						t.Errorf("CheckSubtree rejected wrong th for [%d, %d) in tree of size %d", start, end, n)
					}
				} else if err == nil {
					t.Errorf("CheckSubtree accepted wrong th for [%d, %d) in tree of size %d", start, end, n)
				}

				for i := range len(p) {
					err = torchwood.CheckSubtree(mangleProof(p, i), n, th, start, end, sh)
					if err == nil {
						t.Errorf("CheckSubtree accepted modified proof for [%d, %d) in tree of size %d", start, end, n)
					}
				}

				err = torchwood.CheckSubtree(append(p, tlog.Hash{}), n, th, start, end, sh)
				if err == nil {
					t.Errorf("CheckSubtree accepted extended proof for [%d, %d) in tree of size %d", start, end, n)
				}

				if len(p) == 0 {
					continue
				}

				err = torchwood.CheckSubtree(p[:len(p)-1], n, th, start, end, sh)
				if err == nil {
					t.Errorf("CheckSubtree accepted truncated proof for [%d, %d) in tree of size %d", start, end, n)
				}

				err = torchwood.CheckSubtree(p[1:], n, th, start, end, sh)
				if err == nil {
					t.Errorf("CheckSubtree accepted shifted proof for [%d, %d) in tree of size %d", start, end, n)
				}
			}
		}
	}
	got := o.Sum(nil)
	want := "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
	if fmt.Sprintf("%x", got) != want {
		t.Errorf("AccumulatedSubtreeProof hash = %x; want %s", got, want)
	}
}

func TestAccumulatedRecordInSubtreeProof(t *testing.T) {
	o := sha256.New()
	leaves, tree := buildTree(t, 130)
	for end := int64(0); end <= 130; end++ {
		for start := int64(0); start <= end; start++ {
			if !torchwood.ValidSubtree(start, end) {
				continue
			}
			sh, err := torchwood.SubtreeHash(start, end, tree)
			fatalIfErr(t, err)
			for i := start; i < end; i++ {
				p, err := torchwood.ProveRecordInSubtree(start, end, i, tree)
				fatalIfErr(t, err)

				fmt.Fprintf(o, "%d [%d, %d)", i, start, end)
				for _, h := range p {
					fmt.Fprintf(o, " %x", h[:])
				}
				fmt.Fprintln(o)

				err = torchwood.CheckRecordInSubtree(p, start, end, sh, i, leaves[i])
				fatalIfErr(t, err)

				err = torchwood.CheckRecordInSubtree(p, start, end, sh, i, flip(leaves[i]))
				if err == nil {
					t.Errorf("CheckRecordInSubtree accepted wrong record hash for record %d in [%d, %d)", i, start, end)
				}

				err = torchwood.CheckRecordInSubtree(p, start, end, flip(sh), i, leaves[i])
				if err == nil {
					t.Errorf("CheckRecordInSubtree accepted wrong subtree hash for record %d in [%d, %d)", i, start, end)
				}

				err = torchwood.CheckRecordInSubtree(p, start, end, sh, i+1, leaves[i])
				if err == nil {
					t.Errorf("CheckRecordInSubtree accepted wrong record index for record %d in [%d, %d)", i, start, end)
				}

				for j := range len(p) {
					err = torchwood.CheckRecordInSubtree(mangleProof(p, j), start, end, sh, i, leaves[i])
					if err == nil {
						t.Errorf("CheckRecordInSubtree accepted modified proof for record %d in [%d, %d)", i, start, end)
					}
				}

				err = torchwood.CheckRecordInSubtree(append(p, tlog.Hash{}), start, end, sh, i, leaves[i])
				if err == nil {
					t.Errorf("CheckRecordInSubtree accepted extended proof for record %d in [%d, %d)", i, start, end)
				}
			}
		}
	}
	got := o.Sum(nil)
	want := "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
	if fmt.Sprintf("%x", got) != want {
		t.Errorf("AccumulatedRecordInSubtreeProof hash = %x; want %s", got, want)
	}
}

func mangleProof(p []tlog.Hash, i int) []tlog.Hash {
	p = slices.Clone(p)
	p[i] = flip(p[i])
	return p
}

func TestAccumulatedSubtreeHash(t *testing.T) {
	o := sha256.New()
	_, tree := buildTree(t, 130)
	for end := int64(0); end <= 130; end++ {
		for start := int64(0); start <= end; start++ {
			if !torchwood.ValidSubtree(start, end) {
				continue
			}
			sh, err := torchwood.SubtreeHash(start, end, tree)
			fatalIfErr(t, err)
			fmt.Fprintf(o, "[%d, %d) %x\n", start, end, sh[:])
		}
	}
	got := o.Sum(nil)
	want := "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
	if fmt.Sprintf("%x", got) != want {
		t.Errorf("AccumulatedSubtreeHash hash = %x; want %s", got, want)
	}
}

func TestAccumulatedCoverInterval(t *testing.T) {
	o := sha256.New()
	for end := int64(0); end <= 130; end++ {
		for start := int64(0); start <= end; start++ {
			ls, mid, err := torchwood.CoverInterval(start, end)
			fatalIfErr(t, err)
			fmt.Fprintf(o, "[%d, %d) [%d, %d)\n", ls, mid, mid, end)
		}
	}
	got := o.Sum(nil)
	want := "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
	if fmt.Sprintf("%x", got) != want {
		t.Errorf("AccumulatedCoverInterval hash = %x; want %s", got, want)
	}
}

func TestValidSubtree(t *testing.T) {
	tests := []struct {
		start, end int64
		want       bool
	}{
		{0, 1, true},          // size 1
		{4, 8, true},          // full
		{8, 13, true},         // partial
		{0, 13, true},         // partial, start 0
		{2, 4, true},          // full, size 2
		{6, 8, true},          // full, size 2
		{2, 6, false},         // size 4, 2 not a multiple of 4
		{5, 13, false},        // size 8, 5 not a multiple of 8
		{1, 7, false},         // size 6, 1 not a multiple of 8
		{7, 9, false},         // size 2, 7 not a multiple of 2
		{0, 0, true},          // empty
		{5, 5, true},          // empty, non-zero start
		{5, 3, false},         // end < start
		{-1, 3, false},        // negative start
		{0, 1 << 62, true},    // size 2^62, the maximum span
		{0, 1<<62 + 1, false}, // span over 2^62 would overflow bitCeil
	}
	for _, tt := range tests {
		if got := torchwood.ValidSubtree(tt.start, tt.end); got != tt.want {
			t.Errorf("ValidSubtree(%d, %d) = %v; want %v", tt.start, tt.end, got, tt.want)
		}
	}
}

// refFindSubtrees is a direct port of the find_subtrees Python reference in
// draft-ietf-plants-merkle-tree-certs, Section 4.5.
func refFindSubtrees(start, end int64) [][2]int64 {
	if end-start <= 1 {
		return [][2]int64{{start, end}, {end, end}}
	}
	last := end - 1
	split := bits.Len64(uint64(start^last)) - 1
	mask := int64(1)<<split - 1
	mid := last &^ mask
	leftSplit := bits.Len64(uint64(^start & mask))
	leftStart := start &^ (int64(1)<<leftSplit - 1)
	return [][2]int64{{leftStart, mid}, {mid, end}}
}

func TestCoverInterval(t *testing.T) {
	// Error cases: bad ranges.
	for _, tt := range [][2]int64{{-1, 5}, {5, 3}} {
		if _, _, err := torchwood.CoverInterval(tt[0], tt[1]); err == nil {
			t.Errorf("CoverInterval(%d, %d) = nil error; want error", tt[0], tt[1])
		}
	}

	// Spec worked example: [5, 13) is covered by [4, 8) and [8, 13).
	if ls, mid, err := torchwood.CoverInterval(5, 13); err != nil || ls != 4 || mid != 8 {
		t.Errorf("CoverInterval(5, 13) = %d, %d, %v; want 4, 8, nil", ls, mid, err)
	}

	// Size-one and empty intervals are covered by themselves and an
	// empty subtree.
	if ls, mid, err := torchwood.CoverInterval(7, 8); err != nil || ls != 7 || mid != 8 {
		t.Errorf("CoverInterval(7, 8) = %d, %d, %v; want 7, 8, nil", ls, mid, err)
	}
	if ls, mid, err := torchwood.CoverInterval(5, 5); err != nil || ls != 5 || mid != 5 {
		t.Errorf("CoverInterval(5, 5) = %d, %d, %v; want 5, 5, nil", ls, mid, err)
	}

	// A subtree of size larger than one is covered by its two children.
	if ls, mid, err := torchwood.CoverInterval(4, 8); err != nil || ls != 4 || mid != 6 {
		t.Errorf("CoverInterval(4, 8) = %d, %d, %v; want 4, 6, nil", ls, mid, err)
	}
	if ls, mid, err := torchwood.CoverInterval(0, 13); err != nil || ls != 0 || mid != 8 {
		t.Errorf("CoverInterval(0, 13) = %d, %d, %v; want 0, 8, nil", ls, mid, err)
	}

	for start := range int64(64) {
		for end := start; end <= 64; end++ {
			ls, mid, err := torchwood.CoverInterval(start, end)
			if err != nil {
				t.Errorf("CoverInterval(%d, %d) = %v", start, end, err)
				continue
			}
			// Matches the spec reference.
			if want := refFindSubtrees(start, end); ls != want[0][0] || mid != want[0][1] ||
				want[1][0] != mid || want[1][1] != end {
				t.Errorf("CoverInterval(%d, %d) = %d, %d; want %v", start, end, ls, mid, want)
			}
			// Both halves are valid subtrees.
			if !torchwood.ValidSubtree(ls, mid) || !torchwood.ValidSubtree(mid, end) {
				t.Errorf("CoverInterval(%d, %d) = %d, %d: halves not valid subtrees", start, end, ls, mid)
			}
			// Coverage and bounded excess.
			if !(ls <= start && start <= mid && mid <= end) {
				t.Errorf("CoverInterval(%d, %d) = %d, %d: bad coverage", start, end, ls, mid)
			}
			if start < end && !(start-ls < mid-start) {
				t.Errorf("CoverInterval(%d, %d) = %d, %d: excess %d not less than half of left %d",
					start, end, ls, mid, start-ls, mid-ls)
			}
		}
	}
}

// refMTH computes the RFC 6962 Merkle Tree Hash over the given leaf hashes.
func refMTH(leaves []tlog.Hash) tlog.Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := 1
	for k<<1 < len(leaves) {
		k <<= 1
	}
	return tlog.NodeHash(refMTH(leaves[:k]), refMTH(leaves[k:]))
}

// buildTree builds an in-memory log of n records and returns the leaf hashes and
// a HashReader over the stored hashes.
func buildTree(t *testing.T, n int) (leaves []tlog.Hash, r tlog.HashReader) {
	var stored []tlog.Hash
	r = tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, 0, len(indexes))
		for _, j := range indexes {
			out = append(out, stored[j])
		}
		return out, nil
	})
	if n > 255 {
		panic("buildTree: n too large for test")
	}
	for i := range n {
		data := []byte{byte(i)}
		leaves = append(leaves, tlog.RecordHash(data))
		newHashes, err := tlog.StoredHashes(int64(i), data, r)
		fatalIfErr(t, err)
		stored = append(stored, newHashes...)
	}
	return leaves, r
}

func flip(h tlog.Hash) tlog.Hash {
	h[0] ^= 0xff
	return h
}

func TestSubtreeHash(t *testing.T) {
	const N = 130
	leaves, r := buildTree(t, N)
	for size := int64(1); size <= N; size++ {
		// SubtreeHash(0, size) is the tree hash.
		treeHash, err := tlog.TreeHash(size, r)
		fatalIfErr(t, err)
		if got, err := torchwood.SubtreeHash(0, size, r); err != nil || got != treeHash {
			t.Fatalf("SubtreeHash(0, %d) = %v, %v; want %v", size, got, err, treeHash)
		}
		for start := int64(0); start < size; start++ {
			for end := start + 1; end <= size; end++ {
				if !torchwood.ValidSubtree(start, end) {
					continue
				}
				got, err := torchwood.SubtreeHash(start, end, r)
				fatalIfErr(t, err)
				if want := refMTH(leaves[start:end]); got != want {
					t.Fatalf("SubtreeHash(%d, %d) = %v; want %v", start, end, got, want)
				}
			}
		}
	}
}

func TestSubtreeProof(t *testing.T) {
	const N = 130
	_, r := buildTree(t, N)
	for size := int64(1); size <= N; size++ {
		th, err := tlog.TreeHash(size, r)
		fatalIfErr(t, err)
		for start := int64(0); start < size; start++ {
			for end := start + 1; end <= size; end++ {
				if !torchwood.ValidSubtree(start, end) {
					if _, err := torchwood.ProveSubtree(size, start, end, r); err == nil {
						t.Errorf("ProveSubtree(%d, %d, %d) = nil error for invalid subtree", size, start, end)
					}
					continue
				}
				sh, err := torchwood.SubtreeHash(start, end, r)
				fatalIfErr(t, err)
				p, err := torchwood.ProveSubtree(size, start, end, r)
				fatalIfErr(t, err)
				if err := torchwood.CheckSubtree(p, size, th, start, end, sh); err != nil {
					t.Fatalf("CheckSubtree(size=%d, [%d, %d)) = %v", size, start, end, err)
				}
				// Wrong subtree hash or tree head must fail.
				if torchwood.CheckSubtree(p, size, th, start, end, flip(sh)) == nil {
					t.Errorf("CheckSubtree(size=%d, [%d, %d)) accepted wrong sh", size, start, end)
				}
				if torchwood.CheckSubtree(p, size, flip(th), start, end, sh) == nil {
					t.Errorf("CheckSubtree(size=%d, [%d, %d)) accepted wrong th", size, start, end)
				}
				// A start-0 SubtreeProof is a tlog tree proof.
				if start == 0 {
					tp, err := tlog.ProveTree(size, end, r)
					fatalIfErr(t, err)
					if !slices.Equal([]tlog.Hash(p), tp) {
						t.Errorf("ProveSubtree(%d, 0, %d) != tlog.ProveTree(%d, %d)", size, end, size, end)
					}
				}
				// A size-1 SubtreeProof is a tlog record proof.
				if end == start+1 {
					rp, err := tlog.ProveRecord(size, start, r)
					fatalIfErr(t, err)
					if !slices.Equal([]tlog.Hash(p), rp) {
						t.Errorf("ProveSubtree(%d, %d, %d) != tlog.ProveRecord(%d, %d)", size, start, end, size, start)
					}
				}
			}
		}
	}
}

func TestRecordInSubtree(t *testing.T) {
	const N = 130
	leaves, r := buildTree(t, N)
	// RecordInSubtree proofs do not depend on the tree size, so test every valid
	// subtree of the full tree once.
	for start := range int64(N) {
		for end := start + 1; end <= N; end++ {
			if !torchwood.ValidSubtree(start, end) {
				continue
			}
			sh, err := torchwood.SubtreeHash(start, end, r)
			fatalIfErr(t, err)
			for n := start; n < end; n++ {
				p, err := torchwood.ProveRecordInSubtree(start, end, n, r)
				fatalIfErr(t, err)
				if err := torchwood.CheckRecordInSubtree(p, start, end, sh, n, leaves[n]); err != nil {
					t.Fatalf("CheckRecordInSubtree([%d, %d), n=%d) = %v", start, end, n, err)
				}
				// Wrong subtree hash or record hash must fail.
				if torchwood.CheckRecordInSubtree(p, start, end, flip(sh), n, leaves[n]) == nil {
					t.Errorf("CheckRecordInSubtree([%d, %d), n=%d) accepted wrong sh", start, end, n)
				}
				if torchwood.CheckRecordInSubtree(p, start, end, sh, n, flip(leaves[n])) == nil {
					t.Errorf("CheckRecordInSubtree([%d, %d), n=%d) accepted wrong record hash", start, end, n)
				}
				// A start-0 RecordInSubtree proof is a tlog record proof.
				if start == 0 {
					rp, err := tlog.ProveRecord(end, n, r)
					fatalIfErr(t, err)
					if !slices.Equal([]tlog.Hash(p), rp) {
						t.Errorf("ProveRecordInSubtree(0, %d, %d) != tlog.ProveRecord(%d, %d)", end, n, end, n)
					}
				}
			}
		}
	}
}

func TestEmptySubtree(t *testing.T) {
	_, r := buildTree(t, 16)
	th, err := tlog.TreeHash(16, r)
	fatalIfErr(t, err)

	// An empty subtree hashes to the empty tree hash.
	sh, err := torchwood.SubtreeHash(5, 5, r)
	fatalIfErr(t, err)
	if empty, err := tlog.TreeHash(0, r); err != nil || sh != empty {
		t.Errorf("SubtreeHash(5, 5) = %v, %v; want empty tree hash %v", sh, err, empty)
	}

	// The proof for an empty subtree is empty, and does not depend on the tree.
	p, err := torchwood.ProveSubtree(16, 5, 5, r)
	fatalIfErr(t, err)
	if len(p) != 0 {
		t.Errorf("ProveSubtree(16, 5, 5) = %v; want empty proof", p)
	}
	if err := torchwood.CheckSubtree(p, 16, th, 5, 5, sh); err != nil {
		t.Errorf("CheckSubtree(16, [5, 5)) = %v", err)
	}
	if err := torchwood.CheckSubtree(p, 16, flip(th), 5, 5, sh); err != nil {
		t.Errorf("CheckSubtree(16, [5, 5)) with different th = %v", err)
	}
	if torchwood.CheckSubtree(p, 16, th, 5, 5, flip(sh)) == nil {
		t.Errorf("CheckSubtree accepted wrong hash for empty subtree")
	}
	if torchwood.CheckSubtree(torchwood.SubtreeProof{th}, 16, th, 5, 5, sh) == nil {
		t.Errorf("CheckSubtree accepted non-empty proof for empty subtree")
	}

	// An empty subtree must still be within the tree.
	if _, err := torchwood.ProveSubtree(16, 17, 17, r); err == nil {
		t.Errorf("ProveSubtree(16, 17, 17) = nil error")
	}
	if err := torchwood.CheckSubtree(nil, 16, th, 17, 17, sh); err == nil {
		t.Errorf("CheckSubtree(16, [17, 17)) = nil error")
	}

	// No record is contained in an empty subtree.
	if _, err := torchwood.ProveRecordInSubtree(5, 5, 5, r); err == nil {
		t.Errorf("ProveRecordInSubtree(5, 5, 5) = nil error")
	}
	if err := torchwood.CheckRecordInSubtree(nil, 5, 5, sh, 5, tlog.Hash{}); err == nil {
		t.Errorf("CheckRecordInSubtree([5, 5)) = nil error")
	}
}

func TestSubtreeInvalidInputs(t *testing.T) {
	_, r := buildTree(t, 16)
	// end > t
	if _, err := torchwood.ProveSubtree(8, 0, 16, r); err == nil {
		t.Errorf("ProveSubtree with end > t: nil error")
	}
	// invalid subtree shape
	if _, err := torchwood.ProveSubtree(16, 2, 6, r); err == nil {
		t.Errorf("ProveSubtree with invalid subtree: nil error")
	}
	if _, err := torchwood.SubtreeHash(2, 6, r); err == nil {
		t.Errorf("SubtreeHash with invalid subtree: nil error")
	}
	// record out of subtree range
	if _, err := torchwood.ProveRecordInSubtree(4, 8, 8, r); err == nil {
		t.Errorf("ProveRecordInSubtree with n >= end: nil error")
	}
	if _, err := torchwood.ProveRecordInSubtree(4, 8, 3, r); err == nil {
		t.Errorf("ProveRecordInSubtree with n < start: nil error")
	}

	// Oversized tree size or subtree span must be rejected up front, not drive
	// maxpow2/bitCeil into int64 overflow and hang.
	const tooBig = 1<<62 + 1
	if _, err := torchwood.ProveSubtree(tooBig, 0, 2, r); err == nil {
		t.Errorf("ProveSubtree with t > 2^62: nil error")
	}
	if err := torchwood.CheckSubtree(nil, tooBig, tlog.Hash{}, 0, 2, tlog.Hash{}); err == nil {
		t.Errorf("CheckSubtree with t > 2^62: nil error")
	}
	if _, err := torchwood.SubtreeHash(0, tooBig, r); err == nil {
		t.Errorf("SubtreeHash with span > 2^62: nil error")
	}
	if _, err := torchwood.ProveRecordInSubtree(0, tooBig, 0, r); err == nil {
		t.Errorf("ProveRecordInSubtree with span > 2^62: nil error")
	}
	if err := torchwood.CheckRecordInSubtree(nil, 0, tooBig, tlog.Hash{}, 0, tlog.Hash{}); err == nil {
		t.Errorf("CheckRecordInSubtree with span > 2^62: nil error")
	}
}
