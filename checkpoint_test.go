package torchwood_test

import (
	"strings"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

func TestParseCheckpointOriginLength(t *testing.T) {
	for _, tt := range []struct {
		name   string
		origin string
		valid  bool
	}{
		{"empty", "", false},
		{"one byte", "a", true},
		{"255 bytes", strings.Repeat("a", 255), true},
		{"256 bytes", strings.Repeat("a", 256), false},
		{"255 bytes UTF-8", strings.Repeat("é", 127) + "a", true},
		{"256 bytes UTF-8", strings.Repeat("é", 128), false},
		{"spaces and plus", "example log+origin", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want := torchwood.Checkpoint{
				Origin:    tt.origin,
				Tree:      tlog.Tree{N: 1, Hash: tlog.RecordHash([]byte("entry"))},
				Extension: "extension\n",
			}
			got, err := torchwood.ParseCheckpoint(want.String())
			if !tt.valid {
				if err == nil {
					t.Fatal("ParseCheckpoint accepted an invalid origin length")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("ParseCheckpoint = %+v, want %+v", got, want)
			}
		})
	}
}
