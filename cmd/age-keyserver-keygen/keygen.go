package main

import (
	"crypto/rand"
	"fmt"
	"os"

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

	fmt.Printf("Private key (for LOG_KEY in age-keyserver): %s\n", skey)
	fmt.Printf("Public key (for AGE_KEYSERVER_PUBKEY in age-keylookup): %s\n", vkey)
}
