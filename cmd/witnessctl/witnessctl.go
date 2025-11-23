package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/torchwood/internal/witness"
	"golang.org/x/mod/sumdb/note"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func usage() {
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("    add-log -db <path> -origin <origin>")
	fmt.Println("    add-key -db <path> -origin <origin> -key <verifier key>")
	fmt.Println("    del-key -db <path> -origin <origin> -key <verifier key>")
	fmt.Println("    add-bastion -db <path> -origin <origin> -bastion <address:port>")
	fmt.Println("    del-bastion -db <path> -origin <origin> -bastion <address:port>")
	fmt.Println("    add-sigsum-log -db <path> -key <hex-encoded key>")
	fmt.Println("    pull-logs -db <path> -source <witness url> [-verbose]")
	fmt.Println("    list-logs -db <path>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
	switch os.Args[1] {
	case "add-log":
		originFlag := fs.String("origin", "", "log name")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		addLog(db, *originFlag)
		log.Printf("Added log %q.", *originFlag)

	case "add-key":
		originFlag := fs.String("origin", "", "log name")
		keyFlag := fs.String("key", "", "verifier key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		checkKeyMatches(*originFlag, *keyFlag)
		addKey(db, *originFlag, *keyFlag)
		log.Printf("Added key %q for log %q.", *keyFlag, *originFlag)

	case "del-key":
		originFlag := fs.String("origin", "", "log name")
		keyFlag := fs.String("key", "", "verifier key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		delKey(db, *originFlag, *keyFlag)
		log.Printf("Deleted key %q for log %q.", *keyFlag, *originFlag)

	case "add-bastion":
		originFlag := fs.String("origin", "", "log name")
		bastionFlag := fs.String("bastion", "", "address:port")
		fs.Parse(os.Args[2:])
		checkBastion(*bastionFlag)
		db := openDB(*dbFlag)
		addBastion(db, *originFlag, *bastionFlag)
		log.Printf("Added bastion %q for log %q.", *bastionFlag, *originFlag)

	case "del-bastion":
		originFlag := fs.String("origin", "", "log name")
		bastionFlag := fs.String("bastion", "", "address:port")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		delBastion(db, *originFlag, *bastionFlag)
		log.Printf("Deleted bastion %q for log %q.", *bastionFlag, *originFlag)

	case "add-sigsum-log":
		keyFlag := fs.String("key", "", "hex-encoded key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		addSigsumLog(db, *keyFlag)

	case "pull-logs":
		sourceFlag := fs.String("source", "", "witness network log list URL or file path")
		verboseFlag := fs.Bool("verbose", false, "verbose output")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		pullLogs(db, *sourceFlag, *verboseFlag)

	case "list-logs":
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		listLogs(db)

	default:
		usage()
	}
}

func openDB(dbPath string) *sqlite.Conn {
	db, err := witness.OpenDB(dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	return db
}

func addLog(db *sqlite.Conn, origin string) {
	treeHash := merkle.HashEmptyTree()
	if err := sqlitexExec(db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:])); err != nil {
		log.Fatalf("Error adding log: %v", err)
	}
}

func checkKeyMatches(origin string, vk string) {
	v, err := note.NewVerifier(vk)
	if err != nil {
		log.Fatalf("Error parsing verifier key: %v", err)
	}
	if v.Name() != origin {
		log.Printf("Warning: verifier key name %q does not match origin %q.", v.Name(), origin)
	}
}

func checkBastion(bastion string) {
	if _, _, err := net.SplitHostPort(bastion); err != nil {
		log.Fatalf("Error parsing bastion %q as address:port: %v", bastion, err)
	}
}

func addKey(db *sqlite.Conn, origin string, vk string) {
	err := sqlitexExec(db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, vk)
	if err != nil {
		log.Fatalf("Error adding key: %v", err)
	}
}

func delKey(db *sqlite.Conn, origin string, vk string) {
	err := sqlitexExec(db, "DELETE FROM key WHERE origin = ? AND key = ?", nil, origin, vk)
	if err != nil {
		log.Fatalf("Error deleting key: %v", err)
	}
	if db.Changes() == 0 {
		log.Fatalf("Key %q not found.", vk)
	}
}

func addBastion(db *sqlite.Conn, origin string, bastion string) {
	err := sqlitexExec(db, "INSERT INTO bastion (origin, bastion) VALUES (?, ?)", nil, origin, bastion)
	if err != nil {
		log.Fatalf("Error adding bastion: %v", err)
	}
}

func delBastion(db *sqlite.Conn, origin string, bastion string) {
	err := sqlitexExec(db, "DELETE FROM bastion WHERE origin = ? AND bastion = ?", nil, origin, bastion)
	if err != nil {
		log.Fatalf("Error deleting bastion: %v", err)
	}
	if db.Changes() == 0 {
		log.Fatalf("Bastion %q not found.", bastion)
	}
}

func addSigsumLog(db *sqlite.Conn, keyFlag string) {
	if len(keyFlag) != sigsum.PublicKeySize*2 {
		log.Fatal("Key must be 32 hex-encoded bytes.")
	}
	var key sigsum.PublicKey
	if _, err := hex.Decode(key[:], []byte(keyFlag)); err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	keyHash := sigsum.HashBytes(key[:])
	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	vk, err := note.NewEd25519VerifierKey(origin, key[:])
	if err != nil {
		log.Fatalf("Error computing verifier key: %v", err)
	}
	addLog(db, origin)
	addKey(db, origin, vk)
	log.Printf("Added Sigsum log %q with key %q.", origin, vk)
}

func pullLogs(db *sqlite.Conn, source string, verbose bool) {
	var logList []byte
	if strings.HasPrefix(source, "https://") {
		client := http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			log.Fatalf("Error fetching log list: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Error fetching log list: HTTP %d", resp.StatusCode)
		}
		logList, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading log list: %v", err)
		}
	} else {
		var err error
		logList, err = os.ReadFile(source)
		if err != nil {
			log.Fatalf("Error reading log list: %v", err)
		}
	}
	logs, err := parseLogList(logList, verbose)
	if err != nil {
		log.Fatalf("Error parsing log list: %v", err)
	}
	for origin, vkey := range logs {
		keys, exists := logKeys(db, origin)
		if exists {
			if keys[vkey] {
				// Key already exists, nothing to do.
				if verbose {
					log.Printf("Log %q with key %q already exists, skipping.", origin, vkey)
				}
				continue
			}
			// Key is different, warn.
			log.Printf("Warning: log %q is listed with a different key than the one in the database.\n", origin)
			log.Printf("  - existing keys:\n")
			for k := range keys {
				log.Printf("    - %q\n", k)
			}
			log.Printf("  - new key:\n")
			log.Printf("    - %q\n", vkey)
			continue
		}
		// New log, add it.
		addLog(db, origin)
		addKey(db, origin, vkey)
		if verbose {
			log.Printf("Added log %q with key %q.", origin, vkey)
		}
	}
}

func logKeys(db *sqlite.Conn, origin string) (keys map[string]bool, exists bool) {
	keys = make(map[string]bool)
	if err := sqlitexExec(db, "SELECT 1 FROM log WHERE origin = ?", func(stmt *sqlite.Stmt) error {
		exists = true
		return nil
	}, origin); err != nil {
		log.Fatalf("Error looking for log %q: %v", origin, err)
	}
	if !exists {
		return keys, false
	}
	if err := sqlitexExec(db, "SELECT key FROM key WHERE origin = ?", func(stmt *sqlite.Stmt) error {
		keys[stmt.ColumnText(0)] = true
		return nil
	}, origin); err != nil {
		log.Fatalf("Error querying keys: %v", err)
	}
	return keys, true
}

func listLogs(db *sqlite.Conn) {
	if err := sqlitexExec(db, `
	SELECT json_object(
		'origin', log.origin,
		'size', log.tree_size,
		'root_hash', log.tree_hash,
		'keys', COALESCE(
			json_group_array(key.key) FILTER (WHERE key.key IS NOT NULL),
			json_array()
		),
		'bastions', COALESCE(
			json_group_array(bastion.bastion) FILTER (WHERE bastion.bastion IS NOT NULL),
			json_array()
		))
	FROM
		log
		LEFT JOIN key on log.origin = key.origin
		LEFT JOIN bastion on log.origin = bastion.origin
	GROUP BY
		log.origin
	ORDER BY
		log.origin
	`, func(stmt *sqlite.Stmt) error {
		_, err := fmt.Printf("%s\n", stmt.ColumnText(0))
		return err
	}); err != nil {
		log.Fatalf("Error listing logs: %v", err)
	}
}

func sqlitexExec(conn *sqlite.Conn, query string, resultFn func(stmt *sqlite.Stmt) error, args ...any) error {
	return sqlitex.Execute(conn, query, &sqlitex.ExecOptions{ResultFunc: resultFn, Args: args})
}
