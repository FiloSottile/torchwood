package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"filippo.io/mostly-harmless/vrf-r255"
	"golang.org/x/mod/sumdb/note"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <origin>\n", os.Args[0])
		os.Exit(1)
	}
	origin := os.Args[1]

	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keys: %v\n", err)
		os.Exit(1)
	}

	vrfKey := vrf.GenerateKey()

	fmt.Printf("Private key (for LOG_KEY in age-keyserver): %s\n", skey)
	fmt.Printf("Private VRF key (for VRF_KEY in age-keyserver): %s\n", base64.StdEncoding.EncodeToString(vrfKey.Bytes()))
	fmt.Printf("Public key (for AGE_KEYSERVER_PUBKEY in age-keylookup): %s\n", vkey)
	fmt.Printf("Public VRF key (for AGE_KEYSERVER_VRFKEY in age-keylookup): %s\n", base64.StdEncoding.EncodeToString(vrfKey.PublicKey().Bytes()))
}
