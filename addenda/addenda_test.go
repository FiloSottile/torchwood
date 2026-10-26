package addenda

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestParseIndex runs ParseIndex against the hand-authored vectors in
// testdata/index.txt. See that file's header for the directive format.
func TestParseIndex(t *testing.T) {
	const file = "testdata/index.txt"
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var (
		entry   []byte
		want    [][sha256.Size]byte
		haveRec bool
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
		lineno := i + 1

		switch cmd {
		case "entry":
			entry = decodeHex(t, file, lineno, arg)
			want = nil
			haveRec = true
		case "digest":
			b := decodeHex(t, file, lineno, arg)
			if len(b) != sha256.Size {
				t.Fatalf("%s:%d: digest must be %d bytes, got %d", file, lineno, sha256.Size, len(b))
			}
			want = append(want, [sha256.Size]byte(b))
		case "expect":
			if !haveRec {
				t.Fatalf("%s:%d: expect with no preceding entry", file, lineno)
			}
			got, err := ParseIndex(entry)
			switch arg {
			case "ok":
				if err != nil {
					t.Errorf("%s:%d: ParseIndex(%x) failed: %v", file, lineno, entry, err)
				} else if !slices.Equal(got, want) {
					t.Errorf("%s:%d: ParseIndex(%x) = %x, want %x", file, lineno, entry, got, want)
				}
			case "malformed":
				if err == nil {
					t.Errorf("%s:%d: ParseIndex(%x) succeeded, want malformed", file, lineno, entry)
				}
			default:
				t.Fatalf("%s:%d: unknown expect %q", file, lineno, arg)
			}
			haveRec = false
		default:
			t.Fatalf("%s:%d: unknown directive %q", file, lineno, cmd)
		}
	}
}

func decodeHex(t *testing.T, file string, lineno int, s string) []byte {
	t.Helper()
	if s == "''" {
		return nil
	}
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s:%d: bad hex %q: %v", file, lineno, s, err)
	}
	return b
}

// TestAppendRoundTrip checks that AppendIndex produces entries ParseIndex reads
// back, and that AppendIndex rejects offsets that overrun the entry.
func TestAppendRoundTrip(t *testing.T) {
	var a, b [sha256.Size]byte
	for i := range a {
		a[i], b[i] = 0xaa, 0xbb
	}

	// Two bytes of content, digest a, two bytes, digest b.
	content := append([]byte{0xca, 0xfe}, a[:]...)
	content = append(content, 0xbe, 0xef)
	content = append(content, b[:]...)
	offsets := []uint32{2, 36}

	entry, err := AppendIndex(content, offsets)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIndex(entry)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][sha256.Size]byte{a, b}; !slices.Equal(got, want) {
		t.Errorf("round trip = %x, want %x", got, want)
	}

	// AppendIndex rejects an offset whose digest would overrun the entry.
	if _, err := AppendIndex([]byte{0xca, 0xfe}, []uint32{0}); err == nil {
		t.Errorf("AppendIndex accepted an offset past the end of the entry")
	}

	// The empty-index entry is a single 0x00 byte.
	empty, err := AppendIndex(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, []byte{0x00}) {
		t.Errorf("AppendIndex(nil, nil) = %x, want 00", empty)
	}

	// The count byte caps an index at 255 offsets.
	if _, err := AppendIndex(make([]byte, 32), make([]uint32, 256)); err == nil {
		t.Errorf("AppendIndex accepted 256 offsets")
	}
	full, err := AppendIndex(make([]byte, 32), make([]uint32, 255))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseIndex(full); err != nil || len(got) != 255 {
		t.Errorf("ParseIndex(255-offset entry) = %d digests, %v", len(got), err)
	}
}
