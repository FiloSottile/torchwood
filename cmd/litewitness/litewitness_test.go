package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"litewitness": func() {
			main()
		},
	})
}

func TestScript(t *testing.T) {
	// On macOS, the default TMPDIR is too long for ssh-agent socket paths.
	if runtime.GOOS == "darwin" {
		t.Setenv("TMPDIR", "/tmp")
	}
	p := testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			bindir := filepath.SplitList(os.Getenv("PATH"))[0]
			// Coverage is not collected because of https://go.dev/issue/60182.
			cmd := exec.Command("go", "build", "-o", bindir)
			if testing.CoverMode() != "" {
				cmd.Args = append(cmd.Args, "-cover")
			}
			cmd.Args = append(cmd.Args, "filippo.io/torchwood/cmd/witnessctl")
			cmd.Args = append(cmd.Args, "filippo.io/torchwood/cmd/litebastion")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"waitfor": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: waitfor <file | host:port | URL>")
				}
				if strings.HasPrefix(args[0], "http") {
					var lastErr error
					for i := 0; i < 50; i++ {
						t := http.DefaultTransport.(*http.Transport).Clone()
						t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
						r, err := (&http.Client{Transport: t}).Get(args[0])
						if err == nil && r.StatusCode != http.StatusBadGateway {
							return
						}
						time.Sleep(100 * time.Millisecond)
						lastErr = err
					}
					ts.Fatalf("timeout waiting for %s: %v", args[0], lastErr)
				}
				protocol := "unix"
				if strings.Contains(args[0], ":") {
					protocol = "tcp"
				}
				var lastErr error
				for i := 0; i < 50; i++ {
					conn, err := net.Dial(protocol, args[0])
					if err == nil {
						conn.Close()
						return
					}
					time.Sleep(100 * time.Millisecond)
					lastErr = err
				}
				ts.Fatalf("timeout waiting for %s: %v", args[0], lastErr)
			},
			"killall": func(ts *testscript.TestScript, neg bool, args []string) {
				if neg {
					ts.Fatalf("unsupported: !killall")
				}
				signo := os.Interrupt
				if len(args) > 0 {
					if strings.HasPrefix(args[0], "-") {
						signalName, _ := strings.CutPrefix(args[0][1:], "SIG")

						if signalName == "HUP" {
							signo = syscall.SIGHUP
							args = args[1:]
						} else {
							ts.Fatalf("kill: unknown signal name %q", signalName)
						}
					}
				}
				for _, cmd := range ts.BackgroundCmds() {
					if len(args) > 0 {
						// Only kill processes with this name.
						name := filepath.Base(cmd.Args[0])
						if !slices.Contains(args, name) {
							continue
						}
					}
					cmd.Process.Signal(signo)
				}
			},
			"linecount": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: linecount <file> N")
				}
				count, err := strconv.Atoi(args[1])
				if err != nil {
					ts.Fatalf("invalid count: %v", args[1])
				}
				if got := strings.Count(ts.ReadFile(args[0]), "\n"); got != count {
					ts.Fatalf("%v has %d lines, not %d", args[0], got, count)
				}
			},
		},
	}
	testscript.Run(t, p)
}
