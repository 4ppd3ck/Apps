// Command repolens is the AppDeck app server for RepoLens.
//
// It is a fully native replacement for the former Node.js server (server.js):
// it serves the files in public/ and provides the /api endpoints the frontend
// expects, with the same GitHub caching behavior (memory + disk cache with
// ETag revalidation). No Node runtime is required on any platform.
//
// Usage: repolens [port|--port port|-port=port]   (default 3000)
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var portFlagRE = regexp.MustCompile(`^--?port=(\d+)$`)

// portFromArgs accepts the bare substituted {port} (AppDeck passes it as a
// plain number), plus --port N, -port N, -port=N and --port=N.
func portFromArgs(args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--port" || a == "-port":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 && n < 65536 {
					return n
				}
			}
		case portFlagRE.MatchString(a):
			m := portFlagRE.FindStringSubmatch(a)
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n < 65536 {
				return n
			}
		default:
			if n, err := strconv.Atoi(a); err == nil && n > 0 && n < 65536 {
				return n
			}
		}
	}
	return 0
}

// resolveRoot finds the app folder (the one containing public/): CWD first
// (Android runs the binary with CWD=extracted app folder), then the
// executable's directory and its parent (desktop layout fallbacks).
func resolveRoot() string {
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, exeDir, filepath.Dir(exeDir))
	}
	for _, cand := range candidates {
		if isDir(filepath.Join(cand, "public")) {
			return cand
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return "."
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// loadDotEnv reads simple KEY=VALUE lines from <root>/.env without
// overriding variables that are already set.
func loadDotEnv(root string) {
	raw, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		val := strings.TrimSpace(trimmed[eq+1:])
		val = strings.Trim(val, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

func main() {
	root := resolveRoot()
	loadDotEnv(root)

	port := portFromArgs(os.Args[1:])
	if port == 0 {
		if p, err := strconv.Atoi(os.Getenv("PORT")); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	if port == 0 {
		port = 3000
	}

	dataDir := os.Getenv("REPOLENS_DATA")
	if dataDir == "" {
		dataDir = os.Getenv("APPDECK_DATA")
	}
	if dataDir == "" {
		dataDir = filepath.Join(root, "data")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	srv := &server{
		gh:        newGHClient(dataDir, token),
		publicDir: filepath.Join(root, "public"),
		now:       time.Now,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "repolens: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RepoLens running at http://127.0.0.1:%d\n", port)
	if token != "" {
		fmt.Println("Using GITHUB_TOKEN for higher rate limits.")
	} else {
		fmt.Println("No GITHUB_TOKEN set — unauthenticated limits apply (60 req/hr core, 10 req/min search).")
	}
	if err := http.Serve(ln, http.HandlerFunc(srv.handler)); err != nil {
		fmt.Fprintf(os.Stderr, "repolens: %v\n", err)
		os.Exit(1)
	}
}
