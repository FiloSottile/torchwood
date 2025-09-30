package main

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

func parseLogList(logList []byte, verbose bool) (map[string]string, error) {
	logs := make(map[string]string)
	var sawHeader bool
	var vkey, origin string
	finalizeLogEntry := func() {
		if vkey == "" {
			// The list may be empty.
			return
		}
		defer func() {
			vkey = ""
			origin = ""
		}()
		v, err := note.NewVerifier(vkey)
		if err != nil {
			if verbose {
				log.Printf("Skipping invalid vkey %q: %v", vkey, err)
			}
			return
		}
		if origin == "" {
			origin = v.Name()
		}
		if logs[origin] != "" {
			if verbose {
				log.Printf("Skipping duplicate log entry for %q", origin)
				log.Printf("    - %q", logs[origin])
				log.Printf("    - %q (skipped)", vkey)
			}
			return
		}
		logs[origin] = vkey
	}
	for line := range strings.Lines(string(logList)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			// Comment line, skip.
			continue
		}
		if line == "" {
			// Empty line, skip.
			continue
		}
		if !sawHeader {
			// First non-comment, non-empty line is the header.
			if line != "logs/v0" {
				return nil, fmt.Errorf("invalid log list header: %q", line)
			}
			sawHeader = true
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		if vkey == "" && key != "vkey" {
			return nil, fmt.Errorf("expected vkey entry, got %q", line)
		}
		switch key {
		case "vkey":
			finalizeLogEntry()
			if value == "" {
				return nil, fmt.Errorf("empty vkey entry")
			}
			vkey = value
		case "origin":
			origin = value
		default:
			// Unknown key, ignore.
		}
	}
	finalizeLogEntry()
	return logs, nil
}
