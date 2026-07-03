package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func main() {
	verifyFlag := flag.String("verify", "",
		"verify the file's spicy signature with the given public key")
	keyFlag := flag.String("key", "",
		"the log's private key path (written by -init)")
	initFlag := flag.String("init", "",
		"initialize a new log with the given name (e.g. example.com/spicy)")
	assetsFlag := flag.String("assets", "",
		"directory where log entries and metadata are stored")
	flag.Parse()

	if *verifyFlag != "" {
		if len(flag.Args()) == 0 {
			log.Fatalf("no files to verify")
		}
		vkey, err := note.NewVerifier(*verifyFlag)
		if err != nil {
			log.Fatalf("could not parse public key: %v", err)
		}
		for _, path := range flag.Args() {
			f, err := os.ReadFile(path)
			if err != nil {
				log.Fatalf("could not read %q: %v", path, err)
			}
			sig, err := os.ReadFile(path + ".spicy")
			if err != nil {
				log.Fatalf("could not read %q: %v", path+".spicy", err)
			}
			s := string(sig)
			s, ok := strings.CutPrefix(s, "index ")
			if !ok {
				log.Fatalf("malformed spicy signature for %q", path)
			}
			i, s, ok := strings.Cut(s, "\n")
			if !ok {
				log.Fatalf("malformed spicy signature for %q", path)
			}
			index, err := strconv.ParseInt(i, 10, 64)
			if err != nil {
				log.Fatalf("malformed spicy signature for %q: %v", path, err)
			}
			var proof tlog.RecordProof
			for {
				var h string
				h, s, ok = strings.Cut(s, "\n")
				if !ok {
					log.Fatalf("malformed spicy signature for %q", path)
				}
				if h == "" {
					break
				}
				hh, err := tlog.ParseHash(h)
				if err != nil {
					log.Fatalf("malformed spicy signature for %q: %v", path, err)
				}
				proof = append(proof, hh)
			}
			m, err := note.Open([]byte(s), note.VerifierList(vkey))
			if err != nil {
				log.Fatalf("could not verify checkpoint for %q: %v", path, err)
			}
			c, err := torchwood.ParseCheckpoint(m.Text)
			if err != nil {
				log.Fatalf("could not parse checkpoint for %q: %v", path, err)
			}
			if c.Origin != vkey.Name() {
				log.Fatalf("spicy signature for %q is for a different log: got %q, want %q", path, c.Origin, vkey.Name())
			}
			if err := tlog.CheckRecord(proof, c.N, c.Hash, index, tlog.RecordHash(f)); err != nil {
				log.Fatalf("could not verify inclusion for %q: %v", path, err)
			}
		}
		fmt.Fprintf(os.Stderr, "Spicy signature(s) verified! 🌶️\n")
		return
	}

	if *initFlag != "" {
		latestPath := filepath.Join(*assetsFlag, "latest")
		if _, err := os.Stat(latestPath); err == nil {
			log.Fatalf("log already initialized, %q exists", latestPath)
		}
		edgePath := filepath.Join(*assetsFlag, "edge")
		if _, err := os.Stat(edgePath); err == nil {
			log.Fatalf("log already initialized, %q exists", edgePath)
		}
		if _, err := os.Stat(*keyFlag); err == nil {
			log.Fatalf("log already initialized, %q exists", *keyFlag)
		}

		skey, vkey, err := note.GenerateKey(rand.Reader, *initFlag)
		if err != nil {
			log.Fatalf("could not generate key: %v", err)
		}
		signer, err := note.NewSigner(skey)
		if err != nil {
			log.Fatalf("could not create signer: %v", err)
		}
		checkpoint, err := note.Sign(&note.Note{
			Text: torchwood.Checkpoint{
				Origin: *initFlag,
			}.String(),
		}, signer)
		if err != nil {
			log.Fatalf("could not sign checkpoint: %v", err)
		}

		if err := os.WriteFile(*keyFlag, []byte(skey), 0600); err != nil {
			log.Fatalf("could not write key: %v", err)
		}
		if err := os.WriteFile(latestPath, checkpoint, 0644); err != nil {
			log.Fatalf("could not write latest checkpoint: %v", err)
		}
		if err := os.WriteFile(edgePath, []byte("size 0\n"), 0644); err != nil {
			log.Fatalf("could not write edge: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Log initialized! 🌶️\n")
		fmt.Fprintf(os.Stderr, "  - Name: %s\n", *initFlag)
		fmt.Fprintf(os.Stderr, "  - Public key: %s\n", vkey)
		fmt.Fprintf(os.Stderr, "  - Private key path: %s\n", *keyFlag)
		fmt.Fprintf(os.Stderr, "  - Assets directory: %s\n", *assetsFlag)
		return
	}

	if len(flag.Args()) == 0 {
		log.Fatalf("no files to append")
	}

	skey, err := os.ReadFile(*keyFlag)
	if err != nil {
		log.Fatalf("could not read key: %v", err)
	}
	signer, err := note.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		log.Fatalf("could not parse key: %v", err)
	}
	verifier, err := torchwood.NewVerifierFromSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		log.Fatalf("could not create verifier: %v", err)
	}

	checkpoint, err := os.ReadFile(filepath.Join(*assetsFlag, "latest"))
	if err != nil {
		log.Fatalf("could not read latest checkpoint: %v", err)
	}
	n, err := note.Open(checkpoint, note.VerifierList(verifier))
	if err != nil {
		log.Fatalf("could not verify latest checkpoint: %v", err)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		log.Fatalf("could not parse latest checkpoint: %v", err)
	}

	edgeHashes := make(map[int64]tlog.Hash)
	edgeReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			h, ok := edgeHashes[id]
			if !ok {
				return nil, fmt.Errorf("index %d not in edge", id)
			}
			list = append(list, h)
		}
		return list, nil
	})
	hashReader := torchwood.NewHashReaderOverlay(c.N, edgeReader)

	edge, err := os.ReadFile(filepath.Join(*assetsFlag, "edge"))
	if err != nil {
		log.Fatalf("could not open edge file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(edge)), "\n")
	if len(lines) < 1 {
		log.Fatalf("malformed edge file")
	}
	if size, ok := strings.CutPrefix(lines[0], "size "); !ok {
		log.Fatalf("malformed edge file: %q", lines[0])
	} else {
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			log.Fatalf("malformed edge file: %v", err)
		}
		if n != c.N {
			log.Fatalf("edge file size mismatch: got %d, latest checkpoint is %d", n, c.N)
		}
	}
	idx := torchwood.RightEdge(c.N)
	if len(idx) != len(lines[1:]) {
		log.Fatalf("edge hash count mismatch: got %d, want %d", len(lines[1:]), len(idx))
	}
	for i, line := range lines[1:] {
		hash, err := tlog.ParseHash(line)
		if err != nil {
			log.Fatalf("malformed edge file: %v", err)
		}
		edgeHashes[idx[i]] = hash
	}

	fmt.Fprintf(os.Stderr, "Log loaded.\n")
	fmt.Fprintf(os.Stderr, "  - Name: %s\n", c.Origin)
	fmt.Fprintf(os.Stderr, "  - Current size: %d\n", c.N)
	fmt.Fprintf(os.Stderr, "  - Assets directory: %s\n", *assetsFlag)

	for _, path := range flag.Args() {
		if _, err := os.Stat(path + ".spicy"); err == nil {
			log.Fatalf("spicy signature already exists for %q", path)
		}
		f, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("could not read %q: %v", path, err)
		}
		n := hashReader.Size()
		if err := hashReader.AppendRecordHash(tlog.RecordHash(f)); err != nil {
			log.Fatalf("could not append %q: %v", path, err)
		}
		entryPath := filepath.Join(*assetsFlag, strconv.FormatInt(n, 10))
		if err := os.WriteFile(entryPath, f, 0644); err != nil {
			log.Fatalf("could not copy %q to assets: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "  + %q is now entry %d\n", path, n)
	}

	N := hashReader.Size()
	th, err := tlog.TreeHash(N, hashReader)
	if err != nil {
		log.Fatalf("could not compute tree hash: %v", err)
	}
	newCheckpoint, err := note.Sign(&note.Note{
		Text: torchwood.Checkpoint{
			Origin: c.Origin,
			Tree:   tlog.Tree{N: N, Hash: th},
		}.String()}, signer)
	if err != nil {
		log.Fatalf("could not sign new checkpoint: %v", err)
	}
	newEdge := fmt.Sprintf("size %d\n", N)
	newEdgeHashes, err := hashReader.ReadHashes(torchwood.RightEdge(N))
	if err != nil {
		log.Fatalf("could not read new edge hashes: %v", err)
	}
	for _, h := range newEdgeHashes {
		newEdge += fmt.Sprintf("%s\n", h)
	}

	if err := os.WriteFile(filepath.Join(*assetsFlag, "latest"), newCheckpoint, 0644); err != nil {
		log.Fatalf("could not write new checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*assetsFlag, "edge"), []byte(newEdge), 0644); err != nil {
		log.Fatalf("could not write new edge: %v", err)
	}
	fmt.Fprintf(os.Stderr, "  - New size: %d\n", N)

	for i, path := range flag.Args() {
		s := fmt.Sprintf("index %d\n", c.N+int64(i))
		proof, err := tlog.ProveRecord(N, c.N+int64(i), hashReader)
		if err != nil {
			log.Fatalf("could not prove record %d: %v", c.N+int64(i), err)
		}
		for _, p := range proof {
			s += fmt.Sprintf("%s\n", p)
		}
		s += "\n"
		s += string(newCheckpoint)
		if err := os.WriteFile(path+".spicy", []byte(s), 0644); err != nil {
			log.Fatalf("could not write spicy signature: %v", err)
		}
	}
	fmt.Fprintf(os.Stderr, "Spicy signatures written! 🌶️\n")
}
