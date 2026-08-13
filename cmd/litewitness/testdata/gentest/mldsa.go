//go:build mldsa

// Run with "go run -tags mldsa -mod=mod ./cmd/litewitness/testdata/gentest"
// and re-run "go mod tidy" after use to clean up its dependencies.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"filippo.io/mldsa"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

var seedFlag = flag.String("seed", "", "hex-encoded seed")

func main() {
	origin := "example.com/mldsa-log"

	flag.Parse()
	var seed []byte
	if *seedFlag == "" {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			log.Fatal(err)
		}
	} else {
		seed = make([]byte, hex.DecodedLen(len(*seedFlag)))
		if _, err := hex.Decode(seed, []byte(*seedFlag)); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("- seed: %x\n", seed)

	logKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := torchwood.NewCosignatureSigner(origin, logKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("- log vkey: %s\n", signer.Verifier().String())

	// SignSubtree is used to get a deterministic timestamp (zero).
	rootHash := tlog.RecordHash([]byte("testonly"))
	checkpoint := fmt.Sprintf("%s\n%d\n%s\n", origin, 1, base64.StdEncoding.EncodeToString(rootHash[:]))
	sigLine, err := signer.SignSubtree(origin, 0, 1, rootHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("- checkpoint (size 1):\n%s\n%s", checkpoint, string(sigLine))
}
