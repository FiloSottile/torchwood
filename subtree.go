package torchwood

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"
)

// A SubtreeProof is a verifiable proof that a particular tree head contains a
// particular subtree. A [tlog.TreeProof] is a special case of a SubtreeProof
// where the subtree has start index 0. A [tlog.RecordProof] is a special case
// of a SubtreeProof where the subtree has size 1.
//
// draft-ietf-plants-merkle-tree-certs calls this a "Subtree Consistency
// Proof".
type SubtreeProof []tlog.Hash

// ProveSubtree returns the proof that the tree of size t contains the subtree
// [start, end), where start and end are record indexes.
func ProveSubtree(t, start, end int64, r tlog.HashReader) (SubtreeProof, error) {
	if t < 0 || t > maxN || end > t || !ValidSubtree(start, end) {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveSubtree")
	}
	if start == end {
		// The proof for an empty subtree is empty.
		return SubtreeProof{}, nil
	}
	indexes := subtreeProofIndex(0, t, start, end, true, nil)
	if len(indexes) == 0 {
		return SubtreeProof{}, nil
	}
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(indexes) {
		return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}

	p, hashes := subtreeProof(0, t, start, end, true, hashes)
	if len(hashes) != 0 {
		panic("tlog: bad index math in ProveSubtree")
	}
	return p, nil
}

// subtreeProofIndex builds the list of indexes needed to construct the proof
// that the subtree [start, end) is contained in the node with leaves [lo, hi).
// It appends those indexes to need and returns the result. See
// draft-ietf-plants-merkle-tree-certs, Section 4.4. b reports whether the
// verifier already knows the hash of the subtree portion in [lo, hi); it starts
// true and becomes false past the first straddled node.
func subtreeProofIndex(lo, hi, start, end int64, b bool, need []int64) []int64 {
	if !(lo <= start && start < end && end <= hi) {
		panic("tlog: bad math in subtreeProofIndex")
	}
	if lo == start && hi == end {
		if b {
			return need
		}
		return subTreeIndex(lo, hi, need)
	}
	k, _ := maxpow2(hi - lo)
	switch {
	case end <= lo+k: // subtree in the left child
		need = subtreeProofIndex(lo, lo+k, start, end, b, need)
		need = subTreeIndex(lo+k, hi, need)
	case lo+k <= start: // subtree in the right child
		need = subTreeIndex(lo, lo+k, need)
		need = subtreeProofIndex(lo+k, hi, start, end, b, need)
	default: // subtree straddles the split, which implies start == lo
		if start != lo {
			panic("tlog: bad math in subtreeProofIndex")
		}
		need = subtreeProofIndex(lo+k, hi, lo+k, end, false, need)
		need = subTreeIndex(lo, lo+k, need)
	}
	return need
}

// subtreeProof constructs the proof that the subtree [start, end) is contained
// in the node with leaves [lo, hi). It returns any leftover hashes as well.
func subtreeProof(lo, hi, start, end int64, b bool, hashes []tlog.Hash) (SubtreeProof, []tlog.Hash) {
	if !(lo <= start && start < end && end <= hi) {
		panic("tlog: bad math in subtreeProof")
	}
	if lo == start && hi == end {
		if b {
			// The verifier knows the subtree hash, so we don't need to send it.
			return SubtreeProof{}, hashes
		}
		th, hashes := subTreeHash(lo, hi, hashes)
		return SubtreeProof{th}, hashes
	}
	k, _ := maxpow2(hi - lo)
	var p SubtreeProof
	var th tlog.Hash
	switch {
	case end <= lo+k: // subtree in the left child
		p, hashes = subtreeProof(lo, lo+k, start, end, b, hashes)
		th, hashes = subTreeHash(lo+k, hi, hashes)
	case lo+k <= start: // subtree in the right child
		th, hashes = subTreeHash(lo, lo+k, hashes)
		p, hashes = subtreeProof(lo+k, hi, start, end, b, hashes)
	default: // subtree straddles the split, which implies start == lo
		if start != lo {
			panic("tlog: bad math in subtreeProof")
		}
		p, hashes = subtreeProof(lo+k, hi, lo+k, end, false, hashes)
		th, hashes = subTreeHash(lo, lo+k, hashes)
	}
	return append(p, th), hashes
}

// CheckSubtree verifies that p is a valid proof that the tree of size t
// with hash th contains the subtree [start, end) with hash sh.
func CheckSubtree(p SubtreeProof, t int64, th tlog.Hash, start, end int64, sh tlog.Hash) error {
	if t < 0 || t > maxN || end > t || !ValidSubtree(start, end) {
		return fmt.Errorf("tlog: invalid inputs in CheckSubtree")
	}
	if start == end {
		// An empty subtree is contained in every tree, so th is not checked:
		// the proof must be empty and sh must be the hash of the empty tree.
		if len(p) != 0 || sh != emptyHash {
			return errProofFailed
		}
		return nil
	}
	sh2, th2, err := runSubtreeProof(p, 0, t, start, end, true, sh)
	if err != nil {
		return err
	}
	if sh2 == sh && th2 == th {
		return nil
	}
	return errProofFailed
}

// runSubtreeProof runs the proof p that the subtree [start, end) is contained in
// the node with leaves [lo, hi). Running the proof means constructing and
// returning the implied hashes of both the subtree and the node.
func runSubtreeProof(p SubtreeProof, lo, hi, start, end int64, b bool, sh tlog.Hash) (subtreeHash, nodeHash tlog.Hash, err error) {
	if !(lo <= start && start < end && end <= hi) {
		panic("tlog: bad math in runSubtreeProof")
	}
	if lo == start && hi == end {
		if b {
			// The verifier knows the subtree hash, and it is the node hash.
			if len(p) != 0 {
				return tlog.Hash{}, tlog.Hash{}, errProofFailed
			}
			return sh, sh, nil
		}
		if len(p) != 1 {
			return tlog.Hash{}, tlog.Hash{}, errProofFailed
		}
		return p[0], p[0], nil
	}
	if len(p) == 0 {
		return tlog.Hash{}, tlog.Hash{}, errProofFailed
	}
	k, _ := maxpow2(hi - lo)
	switch {
	case end <= lo+k: // subtree in the left child
		sh2, nh, err := runSubtreeProof(p[:len(p)-1], lo, lo+k, start, end, b, sh)
		if err != nil {
			return tlog.Hash{}, tlog.Hash{}, err
		}
		return sh2, tlog.NodeHash(nh, p[len(p)-1]), nil
	case lo+k <= start: // subtree in the right child
		sh2, nh, err := runSubtreeProof(p[:len(p)-1], lo+k, hi, start, end, b, sh)
		if err != nil {
			return tlog.Hash{}, tlog.Hash{}, err
		}
		return sh2, tlog.NodeHash(p[len(p)-1], nh), nil
	default: // subtree straddles the split, which implies start == lo
		if start != lo {
			panic("tlog: bad math in runSubtreeProof")
		}
		left := p[len(p)-1]
		sh2, nh, err := runSubtreeProof(p[:len(p)-1], lo+k, hi, lo+k, end, false, sh)
		if err != nil {
			return tlog.Hash{}, tlog.Hash{}, err
		}
		return tlog.NodeHash(left, sh2), tlog.NodeHash(left, nh), nil
	}
}

// A RecordInSubtreeProof is a verifiable proof that a particular subtree
// contains a particular record. A [tlog.RecordProof] is a special case of a
// RecordInSubtreeProof where the subtree has start index 0.
//
// draft-ietf-plants-merkle-tree-certs calls this a "Subtree Inclusion Proof".
type RecordInSubtreeProof []tlog.Hash

// ProveRecordInSubtree returns the proof that the subtree [start, end) contains
// the record with index n.
func ProveRecordInSubtree(start, end, n int64, r tlog.HashReader) (RecordInSubtreeProof, error) {
	if !ValidSubtree(start, end) || n < start || n >= end {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveRecordInSubtree")
	}
	indexes := leafProofIndex(start, end, n, nil)
	if len(indexes) == 0 {
		return RecordInSubtreeProof{}, nil
	}
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(indexes) {
		return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}

	p, hashes := leafProof(start, end, n, hashes)
	if len(hashes) != 0 {
		panic("tlog: bad index math in ProveRecordInSubtree")
	}
	return p, nil
}

// CheckRecordInSubtree verifies that p is a valid proof that the subtree
// [start, end) with hash sh contains the record with index n and hash h.
func CheckRecordInSubtree(p RecordInSubtreeProof, start, end int64, sh tlog.Hash, n int64, h tlog.Hash) error {
	if !ValidSubtree(start, end) || n < start || n >= end {
		return fmt.Errorf("tlog: invalid inputs in CheckRecordInSubtree")
	}
	sh2, err := runRecordProof(p, start, end, n, h)
	if err != nil {
		return err
	}
	if sh2 == sh {
		return nil
	}
	return errProofFailed
}

// SubtreeHash computes the hash for the subtree [start, end) using the
// HashReader to obtain previously stored hashes. SubtreeHash makes at most a
// single call to ReadHash requesting at most 1 + log₂(end - start) hashes.
//
// A [tlog.TreeHash] is a special case of a SubtreeHash where start is 0.
// The hash of an empty subtree is the hash of the empty string.
//
// See draft-ietf-plants-merkle-tree-certs, Section 4.
func SubtreeHash(start, end int64, r tlog.HashReader) (tlog.Hash, error) {
	if !ValidSubtree(start, end) {
		return tlog.Hash{}, fmt.Errorf("tlog: invalid inputs in SubtreeHash")
	}
	if start == end {
		return emptyHash, nil
	}
	indexes := subTreeIndex(start, end, nil)
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return tlog.Hash{}, err
	}
	if len(hashes) != len(indexes) {
		return tlog.Hash{}, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}
	hash, hashes := subTreeHash(start, end, hashes)
	if len(hashes) != 0 {
		panic("tlog: bad index math in SubtreeHash")
	}
	return hash, nil
}

// ValidSubtree reports whether [start, end) is a valid subtree. Note that
// empty subtrees [x, x) are valid.
//
// See draft-ietf-plants-merkle-tree-certs, Section 4.
func ValidSubtree(start, end int64) bool {
	if start < 0 || end < start || end-start > maxN {
		return false
	}
	return start == end || start&(bitCeil(end-start)-1) == 0
}

// emptyHash is the hash of the empty tree and of empty subtrees, per
// RFC 6962, Section 2.1. It is the hash of the empty string.
var emptyHash = tlog.Hash(sha256.Sum256(nil))

// CoverInterval returns leftStart and mid for the two subtrees [leftStart, mid)
// and [mid, end) that cover the interval [start, end) as efficiently as
// possible.
//
// The subtrees are adjacent and the second ends at end, but the first may begin
// before start. If the interval has size zero or one, the first subtree is the
// interval itself and the second is empty. If [start, end) is a subtree of size
// larger than one, the two subtrees are its children. See
// draft-ietf-plants-merkle-tree-certs, Section 4.5.
//
// It is an error if start < 0 or end < start.
func CoverInterval(start, end int64) (leftStart, mid int64, err error) {
	if start < 0 || end < start {
		return 0, 0, fmt.Errorf("tlog: invalid interval in CoverInterval")
	}
	if end-start <= 1 {
		return start, end, nil
	}
	last := end - 1
	split := bits.Len64(uint64(start^last)) - 1
	mask := int64(1)<<split - 1
	mid = last &^ mask
	leftSplit := bits.Len64(uint64(^start & mask))
	leftStart = start &^ (int64(1)<<leftSplit - 1)
	return leftStart, mid, nil
}

// maxN is the largest tree size and subtree span the package supports. It is
// the ceiling of [tlog.StoredHashIndex]: a tree of n leaves stores 2n -
// popcount(n) hashes, so a tree of 2^62 leaves fills it exactly (math.MaxInt64
// hashes) and any larger tree overflows int64. bitCeil also overflows past 2^62
// (bitCeil(2^62+1) would round up to 1<<63).
const maxN = 1 << 62

// bitCeil returns the smallest power of two not smaller than n,
// for 1 <= n <= 2^62.
func bitCeil(n int64) int64 {
	return 1 << bits.Len64(uint64(n-1))
}
