package witness

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"sigsum.org/sigsum-go/pkg/merkle"
)

func TestRace(t *testing.T) {
	// gentest seed b4e385f4358f7373cfa9184b176f3cccf808e795baf04092ddfde9461014f0c4
	ss := ed25519.PrivateKey(mustDecodeHex(t,
		"31ffc2116ecbe003acaa800ab70757bd7d53206e3febef6a6d0796d95530b34f"+
			"64848ad8abed6e85981b3b3875b252b8767ebb4b02f703aca3b1e71bbd6a8e50"))
	w, err := NewWitness(":memory:", "example.com", ss, slog.New(testLogHandler(t)))
	fatalIfErr(t, err)
	t.Cleanup(func() { w.Close() })
	pk := mustDecodeHex(t, "ffdc2d4d98e4124d3feaf788c0c2f9abfd796083d1f0495437f302ec79cf100f")
	origin := "sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562"

	treeHash := merkle.HashEmptyTree()
	fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:])))
	k, err := note.NewEd25519VerifierKey(origin, pk[:])
	fatalIfErr(t, err)
	fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, k))

	_, err = w.processAddCheckpointRequest([]byte(`old 0

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
1
KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom7fPZTqpxWWhyjWduBvTvGVqsokMbqTArsQilegKoFBJQjUFAmQ0+YeSPM3wfUQMFSzVnnNuWRTYrajXpNUbIQY=
`), "")
	fatalIfErr(t, err)

	// Stall the first request updating to the shorter size between getting
	// consistency checked and being committed to the database.
	var firstHalf, secondHalf, final sync.Mutex
	firstHalf.Lock()
	secondHalf.Lock()
	final.Lock()
	w.testingOnlyStallRequest = func() {
		firstHalf.Unlock()
		secondHalf.Lock()
	}
	go func() {
		cosig, err := w.processAddCheckpointRequest([]byte(`old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=
`), "")
		if _, ok := err.(*conflictError); !ok {
			t.Errorf("expected conflict, got %v", err)
		}
		if cosig != nil {
			t.Error("returned a cosignature on conflict")
		}
		final.Unlock()
	}()

	// Wait for testingOnlyStallRequest to fire.
	firstHalf.Lock()

	w.testingOnlyStallRequest = nil
	_, err = w.processAddCheckpointRequest([]byte(`old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
+fUDV+k970B4I3uKrqJM4aP1lloPZP8mvr2Z4wRw2LI=
KgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
5
QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIomw/EOJmWi0i1FQsOj+etB7F8IccFam/jgd6wzRns4QPVmyEZtdvl1U2KEmLOZ/ASRcWJi0tW90dJWAShei7sDww=
`), "")
	if err != nil {
		t.Errorf("racing request failed: %v", err)
	}

	// Unblock testingOnlyStallRequest and wait for that request to finish.
	secondHalf.Unlock()
	final.Lock()

	size, hash, err := w.getLog("sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562")
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 {
		t.Error("log got rollbacked")
	}
	if hash != mustDecodeHash(t, "42bb57ad06420afa4882c4a63ac6a1ec77480b330b2f20dfc53a0caa5f564e36") {
		t.Error("unexpected tree hash")
	}
}

func testLogHandler(t testing.TB) slog.Handler {
	h := slog.NewTextHandler(writerFunc(func(p []byte) (n int, err error) {
		t.Logf("%s", p)
		return len(p), nil
	}), &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src := a.Value.Any().(*slog.Source)
				a.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line))
			}
			return a
		},
	})
	return h
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecodeHash(t *testing.T, s string) tlog.Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return *(*tlog.Hash)(b)
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
