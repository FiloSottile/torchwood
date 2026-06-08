package torchwood_test

import (
	"reflect"
	"slices"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

func TestRightEdge(t *testing.T) {
	tests := []struct {
		n    int64
		want []int64
	}{
		{0, nil},
		{13, []int64{
			tlog.StoredHashIndex(3, 0),
			tlog.StoredHashIndex(2, 2),
			tlog.StoredHashIndex(0, 12),
		}},
		{16, []int64{
			tlog.StoredHashIndex(4, 0),
		}},
		{1 << 62, []int64{ // 2^62, the maximum supported tree size
			tlog.StoredHashIndex(62, 0),
		}},
	}
	for _, test := range tests {
		if got := torchwood.RightEdge(test.n); !reflect.DeepEqual(got, test.want) {
			t.Errorf("RightEdge(%d) = %v; want %v", test.n, got, test.want)
		}
	}

	// A tree size beyond 2^62 must panic rather than loop forever in maxpow2.
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("RightEdge(1<<62 + 1) did not panic")
			}
		}()
		torchwood.RightEdge(1<<62 + 1)
	}()
}

func TestHashProof(t *testing.T) {
	var hashes []tlog.Hash
	hashReader := tlog.HashReaderFunc(func(i []int64) ([]tlog.Hash, error) {
		var out []tlog.Hash
		for _, j := range i {
			out = append(out, hashes[j])
		}
		return out, nil
	})

	for n := range int64(256) {
		newHashes, err := tlog.StoredHashes(n, []byte{byte(n)}, hashReader)
		fatalIfErr(t, err)
		hashes = append(hashes, newHashes...)

		rootHash, err := tlog.TreeHash(n+1, hashReader)
		fatalIfErr(t, err)

		for i := range len(hashes) {
			proof, err := torchwood.ProveHash(n+1, int64(i), hashReader)
			fatalIfErr(t, err)

			if err := torchwood.CheckHash(proof, n+1, rootHash, int64(i), hashes[i]); err != nil {
				t.Errorf("hash proof mismatch for size %d, hash index %d: %v", n+1, i, err)
			}

			if l, k := tlog.SplitStoredHashIndex(int64(i)); l == 0 {
				recordProof, err := tlog.ProveRecord(n+1, k, hashReader)
				fatalIfErr(t, err)

				if !slices.Equal([]tlog.Hash(proof), recordProof) {
					t.Errorf("record proof mismatch for size %d, record index %d", n+1, k)
				}
			}
		}
	}

	// Oversized tree size must be rejected, not hang. (ProveHash/CheckHash
	// delegate the bound to ProveSubtree/CheckSubtree.)
	if _, err := torchwood.ProveHash(1<<62+1, 0, hashReader); err == nil {
		t.Errorf("ProveHash with t > 2^62: nil error")
	}
	if err := torchwood.CheckHash(nil, 1<<62+1, tlog.Hash{}, 0, tlog.Hash{}); err == nil {
		t.Errorf("CheckHash with t > 2^62: nil error")
	}
}

func fatalIfErr(t *testing.T, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("unexpected error: %v", err)
	}
}
