// Package addenda implements the digest indication format of c2sp.org/tlog-addenda.
//
// A transparency log may commit to data held outside its entries -- an
// addendum -- by placing the addendum's SHA-256 digest inside a log entry. The
// digest indication format is a compact structure suffixed to an entry that
// tells generic tooling where those 32-byte digests sit within the entry, so
// they can be located without any knowledge of the entry's own encoding.
//
// The format is read from the end of an entry, backwards:
//
//	<application content, including the digests> || offset_0 || ... || offset_{N-1} || N
//
// The final byte is a count N of digests, from 0 to 255. The preceding N*4
// bytes are the offsets, each a 4-byte big-endian position from the start of
// the entry where a 32-byte digest appears. offset_0 is first in byte order,
// farthest from the count byte. An entry with no addenda is its application
// content followed by a single 0x00 byte.
//
// Reading is self-locating and never depends on the order of the offsets.
package addenda

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// AppendIndex appends a digest indication index to entry and returns the
// result, according to c2sp.org/tlog-addenda.
//
// Each offset is a byte position from the start of entry where a 32-byte
// SHA-256 digest already appears. AppendIndex does not write or hash the
// digests; the caller is responsible for having placed them in entry.
//
// It returns an error if there are more than 255 offsets, or if any offset
// would place a digest past the end of entry.
func AppendIndex(entry []byte, offsets []uint32) ([]byte, error) {
	if len(offsets) > 255 {
		return nil, fmt.Errorf("tlog-addenda: too many digest offsets: %d", len(offsets))
	}
	for _, off := range offsets {
		if int64(off)+sha256.Size > int64(len(entry)) {
			return nil, fmt.Errorf("tlog-addenda: digest offset %d past end of %d-byte entry", off, len(entry))
		}
	}
	for _, off := range offsets {
		entry = binary.BigEndian.AppendUint32(entry, off)
	}
	return append(entry, byte(len(offsets))), nil
}

// ParseIndex reads the digest indication index from the end of entry and
// returns the digests it points to, in index order, according to
// c2sp.org/tlog-addenda.
//
// An entry with no addenda ends in a single 0x00 byte, for which ParseIndex
// returns no digests.
//
// ParseIndex rejects an empty entry, an entry too short to hold the offsets it
// declares, and any offset whose digest would not lie entirely within the
// application content before the index. It places no other constraint on the
// offsets; duplicate, overlapping, and unsorted offsets are all valid.
func ParseIndex(entry []byte) ([][sha256.Size]byte, error) {
	if len(entry) < 1 {
		return nil, errors.New("tlog-addenda: entry is empty")
	}
	n := int(entry[len(entry)-1])
	rest := entry[:len(entry)-1]
	if len(rest) < n*4 {
		return nil, fmt.Errorf("tlog-addenda: entry too short for %d digest offsets", n)
	}
	content := rest[:len(rest)-n*4]
	offsets := rest[len(rest)-n*4:]
	digests := make([][sha256.Size]byte, n)
	for i := range n {
		off := int64(binary.BigEndian.Uint32(offsets[i*4:]))
		if off+sha256.Size > int64(len(content)) {
			return nil, fmt.Errorf("tlog-addenda: digest offset %d past end of %d-byte content", off, len(content))
		}
		digests[i] = [sha256.Size]byte(content[off : off+sha256.Size])
	}
	return digests, nil
}
