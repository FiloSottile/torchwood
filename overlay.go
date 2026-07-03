package torchwood

import (
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

// A HashReaderOverlay is a [tlog.HashReader] for a tree that extends an
// original tree with appended records, whose stored hashes are held in memory.
//
// It can be used to stage the hashes of new records before they are persisted,
// and to compute tree hashes, subtree hashes, proofs, and tiles that span both
// the original tree and the appended records.
//
// The underlying HashReader is responsible for serving any requested hashes in
// the original tree. Which hashes are requested depends on the caller:
// [HashReaderOverlay.AppendRecordHash], [tlog.StoredHashes], [tlog.TreeHash],
// and [SubtreeHash] only need the [RightEdge] of the original tree (as long as
// the tree or subtree extends past the original tree), while
// [tlog.ReadTileData] might need more (such as the full contents of the
// rightmost tiles).
type HashReaderOverlay struct {
	r      tlog.HashReader
	size   int64
	base   int64 // tlog.StoredHashCount of the original tree size
	hashes []tlog.Hash
}

// NewHashReaderOverlay returns a [HashReaderOverlay] over an original tree of
// size n, whose hashes are served by r. If n is 0, r may be nil.
//
// n must not be negative or greater than 2^62, the largest supported tree
// size; NewHashReaderOverlay panics otherwise.
func NewHashReaderOverlay(n int64, r tlog.HashReader) *HashReaderOverlay {
	if n < 0 || n > maxN {
		panic("tlog: tree size out of range in NewHashReaderOverlay")
	}
	return &HashReaderOverlay{r: r, size: n, base: tlog.StoredHashCount(n)}
}

// Size returns the size of the extended tree: the size of the original tree
// plus the number of appended leaf records.
func (o *HashReaderOverlay) Size() int64 {
	return o.size
}

// AppendRecordHash extends the tree by one record with the given record hash
// (as produced by [tlog.RecordHash]), computing and adding the record's stored
// hashes to the overlay.
//
// The hashes of completed subtrees may be requested from the overlay, which
// needs at most the [RightEdge] of the original tree from the underlying
// HashReader.
func (o *HashReaderOverlay) AppendRecordHash(rh tlog.Hash) error {
	if o.size >= maxN {
		return fmt.Errorf("tlog: tree size out of range in AppendRecordHash")
	}
	hashes, err := tlog.StoredHashesForRecordHash(o.size, rh, o)
	if err != nil {
		return err
	}
	o.hashes = append(o.hashes, hashes...)
	o.size++
	return nil
}

// ReadHashes implements [tlog.HashReader]. Any hashes in the original tree are
// requested from the underlying HashReader in a single ReadHashes call.
func (o *HashReaderOverlay) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	list := make([]tlog.Hash, len(indexes))
	var origIndexes []int64
	var origPositions []int
	for i, id := range indexes {
		switch {
		case id < 0 || id >= o.base+int64(len(o.hashes)):
			return nil, fmt.Errorf("tlog: index %d out of range for tree of size %d in HashReaderOverlay", id, o.size)
		case id < o.base:
			origIndexes = append(origIndexes, id)
			origPositions = append(origPositions, i)
		default:
			list[i] = o.hashes[id-o.base]
		}
	}
	if len(origIndexes) > 0 {
		if o.r == nil {
			return nil, fmt.Errorf("tlog: no underlying HashReader for original tree in HashReaderOverlay")
		}
		hashes, err := o.r.ReadHashes(origIndexes)
		if err != nil {
			return nil, err
		}
		if len(hashes) != len(origIndexes) {
			return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(origIndexes), len(hashes))
		}
		for i, h := range hashes {
			list[origPositions[i]] = h
		}
	}
	return list, nil
}
