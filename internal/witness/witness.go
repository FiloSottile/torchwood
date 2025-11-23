package witness

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type Witness struct {
	s   *torchwood.CosignatureSigner
	mux *http.ServeMux
	log *slog.Logger

	dmMu sync.Mutex
	db   *sqlite.Conn

	// testingOnlyStallRequest is called after checking a valid tree head, but
	// before committing it to the database. It's used in tests to cause a race
	// between two requests and simulating the risk of a rollback.
	testingOnlyStallRequest func()
}

func OpenDB(dbPath string) (*sqlite.Conn, error) {
	db, err := sqlite.OpenConn(dbPath, 0)
	if err != nil {
		return nil, fmt.Errorf("opening database: %v", err)
	}

	return db, sqlitex.ExecScript(db, `
		PRAGMA strict_types = ON;
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS log (
			origin TEXT PRIMARY KEY,
			tree_size INTEGER NOT NULL,
			tree_hash TEXT NOT NULL -- base64-encoded
		);
		CREATE TABLE IF NOT EXISTS key (
			origin TEXT NOT NULL,
			key TEXT NOT NULL, -- note verifier key
			FOREIGN KEY(origin) REFERENCES log(origin)
		);
		CREATE TABLE IF NOT EXISTS bastion (
			origin TEXT NOT NULL,
			bastion TEXT NOT NULL, -- addr:port
			FOREIGN KEY(origin) REFERENCES log(origin)
		);
	`)
}

func NewWitness(dbPath, name string, key crypto.Signer, log *slog.Logger) (*Witness, error) {
	db, err := OpenDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("initializing database: %v", err)
	}

	s, err := torchwood.NewCosignatureSigner(name, key)
	if err != nil {
		return nil, fmt.Errorf("preparing signer: %v", err)
	}

	w := &Witness{
		db:  db,
		s:   s,
		log: log,
		mux: http.NewServeMux(),
	}
	w.mux.Handle("POST /add-checkpoint", http.HandlerFunc(w.serveAddCheckpoint))
	return w, nil
}

func (w *Witness) Close() error {
	w.dmMu.Lock()
	defer w.dmMu.Unlock()
	return w.db.Close()
}

func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mux.ServeHTTP(rw, r)
}

func (w *Witness) VerifierKey() string {
	return w.s.Verifier().String()
}

func (w *Witness) AllBastions() ([]string, error) {
	var bastions []string
	err := w.dbExec("SELECT DISTINCT bastion FROM bastion",
		func(stmt *sqlite.Stmt) error {
			bastions = append(bastions, stmt.GetText("bastion"))
			return nil
		})
	return bastions, err

}

type conflictError struct {
	known int64
}

func (*conflictError) Error() string { return "known tree size doesn't match provided old size" }

var errUnknownLog = errors.New("unknown log")
var errWrongBastion = errors.New("rejected request, bad/missing bastion")
var errInvalidSignature = errors.New("invalid signature")
var errBadRequest = errors.New("invalid input")
var errProof = errors.New("bad consistency proof")

type viaBastionKey struct{}

func ContextWithBastion(ctx context.Context, bastion string) context.Context {
	return context.WithValue(ctx, viaBastionKey{}, bastion)
}

func ContextBastion(ctx context.Context) string {
	if bastion, ok := ctx.Value(viaBastionKey{}).(string); ok {
		return bastion
	}
	return ""
}

func (w *Witness) serveAddCheckpoint(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.log.DebugContext(r.Context(), "error reading request body", "error", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	cosig, err := w.processAddCheckpointRequest(body, ContextBastion(r.Context()))
	if err, ok := err.(*conflictError); ok {
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(http.StatusConflict)
		fmt.Fprintf(rw, "%d\n", err.known)
		return
	}
	switch err {
	case errUnknownLog, errInvalidSignature, errWrongBastion:
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	case errBadRequest:
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case errProof:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := rw.Write(cosig); err != nil {
		w.log.DebugContext(r.Context(), "error writing response", "error", err)
	}
}

func (w *Witness) processAddCheckpointRequest(body []byte, bastion string) (cosig []byte, err error) {
	l := w.log.With("request", string(body))
	defer func() {
		if err != nil {
			l = l.With("error", err)
		}
		l.Debug("processed add-checkpoint request")
	}()
	body, noteBytes, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, errBadRequest
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 1 {
		return nil, errBadRequest
	}
	size, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return nil, errBadRequest
	}
	oldSize, err := strconv.ParseInt(size, 10, 64)
	if err != nil || oldSize < 0 {
		return nil, errBadRequest
	}
	l = l.With("oldSize", oldSize)
	proof := make(tlog.TreeProof, len(lines[1:]))
	for i, h := range lines[1:] {
		proof[i], err = tlog.ParseHash(h)
		if err != nil {
			return nil, errBadRequest
		}
	}
	origin, _, _ := strings.Cut(string(noteBytes), "\n")
	l = l.With("origin", origin)
	bastions, err := w.getBastions(origin)
	if err != nil {
		return nil, err
	}
	if bastion != "" && !slices.Contains(bastions, bastion) {
		l.Debug("rejected request from unexpected bastion", "bastion", bastion)
		return nil, errWrongBastion
	}
	verifier, err := w.getKeys(origin)
	if err != nil {
		return nil, err
	}
	n, err := note.Open(noteBytes, verifier)
	switch err.(type) {
	case *note.UnverifiedNoteError, *note.InvalidSignatureError:
		return nil, errInvalidSignature
	}
	if err != nil {
		return nil, err
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	l = l.With("size", c.N)
	if err := w.checkConsistency(c.Origin, oldSize, c.N, c.Hash, proof); err != nil {
		return nil, err
	}
	if w.testingOnlyStallRequest != nil {
		w.testingOnlyStallRequest()
	}
	if err := w.persistTreeHead(c.Origin, oldSize, c.N, c.Hash); err != nil {
		return nil, err
	}
	signed, err := note.Sign(&note.Note{Text: n.Text}, w.s)
	if err != nil {
		return nil, err
	}
	sigs, err := splitSignatures(signed)
	if err != nil {
		return nil, err
	}
	return sigs, err
}

func splitSignatures(note []byte) ([]byte, error) {
	var sigSplit = []byte("\n\n")
	split := bytes.LastIndex(note, sigSplit)
	if split < 0 {
		return nil, errors.New("invalid note")
	}
	_, sigs := note[:split+1], note[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errors.New("invalid note")
	}
	return sigs, nil
}

func (w *Witness) checkConsistency(origin string,
	oldSize, newSize int64, newHash tlog.Hash, proof tlog.TreeProof) error {
	if oldSize > newSize {
		return errBadRequest
	}
	knownSize, oldHash, err := w.getLog(origin)
	if err != nil {
		return err
	}
	if knownSize != oldSize {
		return &conflictError{knownSize}
	}
	if oldSize == 0 {
		// This is the first tree head for this log.
		return nil
	}
	if err := tlog.CheckTree(proof, newSize, newHash, oldSize, oldHash); err != nil {
		return errProof
	}
	return nil
}

func (w *Witness) persistTreeHead(origin string, oldSize, newSize int64, newHash tlog.Hash) error {
	// Check oldSize against the database to prevent rolling back on a race.
	// Alternatively, we could use a database transaction which would be cleaner
	// but would encode a critical security semantic in the implicit use of the
	// correct Conn across functions, which is uncomfortable.
	changes, err := w.dbExecWithChanges(`
			UPDATE log SET tree_size = ?, tree_hash = ?
			WHERE origin = ? AND tree_size = ?`,
		nil, newSize, newHash, origin, oldSize)
	if err == nil && changes != 1 {
		knownSize, _, err := w.getLog(origin)
		if err != nil {
			return err
		}
		return &conflictError{knownSize}
	}
	return err
}

func (w *Witness) getLog(origin string) (treeSize int64, treeHash tlog.Hash, err error) {
	found := false
	err = w.dbExec("SELECT tree_size, tree_hash FROM log WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			found = true
			treeSize = stmt.GetInt64("tree_size")
			treeHash, err = tlog.ParseHash(stmt.GetText("tree_hash"))
			return nil
		}, origin)
	if err == nil && !found {
		err = errUnknownLog
	}
	return
}

func (w *Witness) getKeys(origin string) (note.Verifiers, error) {
	var keys []string
	err := w.dbExec("SELECT key FROM key WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			keys = append(keys, stmt.GetText("key"))
			return nil
		}, origin)
	if err == nil && keys == nil {
		err = errUnknownLog
	}
	if err != nil {
		return nil, err
	}
	var verifiers []note.Verifier
	for _, k := range keys {
		v, err := note.NewVerifier(k)
		if err != nil {
			w.log.Warn("invalid key in database", "key", k, "error", err)
			return nil, fmt.Errorf("invalid key %q: %v", k, err)
		}
		verifiers = append(verifiers, v)
	}
	return note.VerifierList(verifiers...), nil
}

func (w *Witness) getBastions(origin string) ([]string, error) {
	var bastions []string
	err := w.dbExec("SELECT bastion FROM bastion WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			bastions = append(bastions, stmt.GetText("bastion"))
			return nil
		}, origin)
	return bastions, err
}

func (w *Witness) dbExec(query string, resultFn func(stmt *sqlite.Stmt) error, args ...interface{}) error {
	w.dmMu.Lock()
	defer w.dmMu.Unlock()
	err := sqlitexExec(w.db, query, resultFn, args...)
	if err != nil {
		w.log.Error("database error", "error", err)
	}
	return err
}

func (w *Witness) dbExecWithChanges(query string, resultFn func(stmt *sqlite.Stmt) error, args ...interface{}) (int, error) {
	w.dmMu.Lock()
	defer w.dmMu.Unlock()
	err := sqlitexExec(w.db, query, resultFn, args...)
	if err != nil {
		w.log.Error("database error", "error", err)
		return 0, err
	}
	return w.db.Changes(), nil
}

func sqlitexExec(conn *sqlite.Conn, query string, resultFn func(stmt *sqlite.Stmt) error, args ...any) error {
	return sqlitex.Execute(conn, query, &sqlitex.ExecOptions{ResultFunc: resultFn, Args: args})
}
