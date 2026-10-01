package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestTooManyProofs(t *testing.T) {
	// gentest seed b4e385f4358f7373cfa9184b176f3cccf808e795baf04092ddfde9461014f0c4
	ss := ed25519.PrivateKey(mustDecodeHex(t,
		"31ffc2116ecbe003acaa800ab70757bd7d53206e3febef6a6d0796d95530b34f"+
			"64848ad8abed6e85981b3b3875b252b8767ebb4b02f703aca3b1e71bbd6a8e50"))
	w, err := NewWitness(":memory:", "example.com", ss, slog.New(testLogHandler(t)))
	fatalIfErr(t, err)
	t.Cleanup(func() { w.Close() })
	origin := "sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562"

	treeHash := merkle.HashEmptyTree()
	fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:])))
	pk := mustDecodeHex(t, "ffdc2d4d98e4124d3feaf788c0c2f9abfd796083d1f0495437f302ec79cf100f")
	k, err := note.NewEd25519VerifierKey(origin, pk[:])
	fatalIfErr(t, err)
	fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, k))

	// make checkpoint with > 63 proofs
	buf := []byte("old 0\n")
	proofs := bytes.Repeat([]byte("KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 64)
	buf = append(buf, proofs...)
	rest := []byte(`
sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
1
KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom7fPZTqpxWWhyjWduBvTvGVqsokMbqTArsQilegKoFBJQjUFAmQ0+YeSPM3wfUQMFSzVnnNuWRTYrajXpNUbIQY=
`)
	buf = append(buf, rest...)
	_, err = w.processAddCheckpointRequest(buf, "")
	if err == nil || err != errBadRequest {
		t.Fatal("checkpoint with too many proofs (>63) should have failed with bad request")
	}
}

func TestZeroSize(t *testing.T) {
	const origin = "example.com/log"
	sk, vk, err := note.GenerateKey(rand.Reader, origin)
	fatalIfErr(t, err)
	signer, err := note.NewSigner(sk)
	fatalIfErr(t, err)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	emptyHash := tlog.Hash(merkle.HashEmptyTree())
	leafHash := tlog.RecordHash([]byte("leaf"))
	for _, tt := range []struct {
		name                        string
		knownSize, oldSize, newSize int64
		hash                        tlog.Hash
		proof                       tlog.TreeProof
		status                      int
	}{
		{name: "empty tree", hash: emptyHash, status: http.StatusOK},
		{name: "invalid empty root", hash: leafHash, status: http.StatusUnprocessableEntity},
		{name: "zero empty root", status: http.StatusUnprocessableEntity},
		{name: "empty tree with proof", hash: emptyHash, proof: tlog.TreeProof{leafHash}, status: http.StatusUnprocessableEntity},
		{name: "first nonempty tree", newSize: 1, hash: leafHash, status: http.StatusOK},
		{name: "first nonempty tree with proof", newSize: 1, hash: leafHash, proof: tlog.TreeProof{leafHash}, status: http.StatusUnprocessableEntity},
		{name: "old size mismatch", knownSize: 1, newSize: 1, hash: leafHash, proof: tlog.TreeProof{leafHash}, status: http.StatusConflict},
		{name: "old size greater than new", knownSize: 1, oldSize: 1, hash: emptyHash, status: http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWitness(":memory:", "example.com/witness", key, slog.New(testLogHandler(t)))
			fatalIfErr(t, err)
			t.Cleanup(func() { w.Close() })
			knownHash := emptyHash
			if tt.knownSize != 0 {
				knownHash = leafHash
			}
			fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, ?, ?)", nil, origin, tt.knownSize, knownHash))
			fatalIfErr(t, sqlitexExec(w.db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, vk))
			text := fmt.Sprintf("%s\n%d\n%s\n", origin, tt.newSize, tt.hash)
			signed, err := note.Sign(&note.Note{Text: text}, signer)
			fatalIfErr(t, err)
			var body bytes.Buffer
			fmt.Fprintf(&body, "old %d\n", tt.oldSize)
			for _, hash := range tt.proof {
				fmt.Fprintf(&body, "%s\n", hash)
			}
			body.WriteByte('\n')
			body.Write(signed)
			// Repeat to also exercise an already cosigned empty checkpoint.
			for range 2 {
				rw := httptest.NewRecorder()
				w.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/add-checkpoint", bytes.NewReader(body.Bytes())))
				wantStatus := tt.status
				if tt.status == http.StatusOK && tt.newSize != 0 {
					// Use the matching old size on the second submission.
					body.Reset()
					fmt.Fprintf(&body, "old %d\n\n%s", tt.newSize, signed)
				}
				if rw.Code != wantStatus {
					t.Fatalf("status = %d, want %d: %s", rw.Code, wantStatus, rw.Body.String())
				}
				size, hash, err := w.getLog(origin)
				fatalIfErr(t, err)
				wantSize, wantHash := tt.knownSize, knownHash
				if tt.status == http.StatusOK {
					wantSize, wantHash = tt.newSize, tt.hash
					_, err := note.Open(append(bytes.Clone(signed), rw.Body.Bytes()...), note.VerifierList(w.s.Verifier()))
					fatalIfErr(t, err)
				} else if bytes.Contains(rw.Body.Bytes(), []byte("— ")) {
					t.Fatal("returned a cosignature on error")
				}
				if size != wantSize || hash != wantHash {
					t.Fatalf("stored tree = (%d, %s), want (%d, %s)", size, hash, wantSize, wantHash)
				}
			}
		})
	}
}
