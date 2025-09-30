// Run with "go run -mod=mod ./cmd/litewitness/testdata/gentest"
// and re-run "go mod tidy" after use to clean up its dependencies.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/url"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

var seedFlag = flag.String("seed", "", "hex-encoded seed")

func main() {
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
	h := hkdf.New(sha256.New, seed, []byte("litewitness gentest"), nil)

	publicKey, privateKey, _ := ed25519.GenerateKey(h)
	fmt.Printf("- log private key: %x\n", privateKey.Seed())
	fmt.Printf("- log public key: %x\n", publicKey)

	keyHash := sigsum.HashBytes(publicKey[:])
	fmt.Printf("- log key hash: %x\n", keyHash)
	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	fmt.Printf("- origin: %s\n", origin)
	fmt.Printf("- origin URL-encoded: %s\n", url.QueryEscape(origin))

	const algEd25519 = 1
	kh := noteKeyHash(origin, append([]byte{algEd25519}, publicKey...))
	vkey := fmt.Sprintf("%s+%08x+%s", origin, kh, base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, publicKey...)))
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", origin, kh, base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, privateKey.Seed()...)))
	s, _ := note.NewSigner(skey)
	fmt.Printf("- log note vkey: %s\n", vkey)
	fmt.Printf("- log note key: %s\n", skey)

	witSeed := make([]byte, ed25519.SeedSize)
	h.Read(witSeed)
	witKey := ed25519.NewKeyFromSeed(witSeed)
	ss, err := ssh.NewSignerFromSigner(witKey)
	if err != nil {
		log.Fatal(err)
	}
	pkHash := sigsum.HashBytes(ss.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))
	fmt.Printf("- witness key hash: %s\n", hex.EncodeToString(pkHash[:]))
	fmt.Printf("- witness key: %x\n", witKey)
	pemKey, err := ssh.MarshalPrivateKey(witKey, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("- witness key:\n%s", pem.EncodeToMemory(pemKey))

	tree := merkle.NewTree()
	addLeaf := func(leaf sigsum.Hash) {
		if !tree.AddLeafHash(&leaf) {
			panic("duplicate")
		}
		fmt.Printf("- leaf[%d] hash: %x\n", tree.Size(), leaf)
	}
	signTreeHead := func() {
		checkpoint := fmt.Sprintf("%s\n%d\n%s\n", origin, tree.Size(), tlog.Hash(tree.GetRootHash()))
		n, _ := note.Sign(&note.Note{Text: checkpoint}, s)
		fmt.Printf("- checkpoint (size %d):\n%s\n", tree.Size(), n)
	}
	consistencyProof := func(oldSize uint64) {
		proof, err := tree.ProveConsistency(oldSize, tree.Size())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("- consistency proof from size %d:\n", oldSize)
		fmt.Printf("old %d\n", oldSize)
		for _, p := range proof {
			fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(p[:]))
		}
	}

	addLeaf(sigsum.Hash{42, 0})
	signTreeHead()

	addLeaf(sigsum.Hash{42, 1})
	addLeaf(sigsum.Hash{42, 2})
	signTreeHead()
	consistencyProof(1)

	addLeaf(sigsum.Hash{42, 3})
	addLeaf(sigsum.Hash{42, 4})
	signTreeHead()
	consistencyProof(1)
	consistencyProof(3)
}

func noteKeyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
