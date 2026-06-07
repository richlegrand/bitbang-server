package handler

import (
	"net/http"
	"path/filepath"
	"strings"
)

// allowedBitbangAssets is the whitelist of files served at /__bitbang__/<file>.
// Anything else returns 404. Matches signaling.py exactly.
var allowedBitbangAssets = map[string]bool{
	"sw.js":         true,
	"bootstrap.js":  true,
	"ws-shim.js":    true,
	"xhr-shim.js":   true,
	"favicon.ico":   true, // handler internally maps this to favicon.png
}

// Static returns an http.Handler that serves the signaling server's static
// assets from staticDir. Routes mirror Python signaling.py:
//
//	GET /favicon.ico            -> favicon.png
//	GET /__bitbang__/<file>     -> whitelisted assets with no-cache headers
//	GET /<uid>                  -> bootstrap.html  (or <uid>.js if uid ends in .js)
//	GET /<uid>/<subpath>        -> bootstrap.html
//
// /status and /ws/... are routed elsewhere (this handler is the catch-all).
func Static(staticDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.Path

		switch {
		case path == "/favicon.ico":
			serveFile(w, r, staticDir, "favicon.png", "image/png", false)
			return

		case strings.HasPrefix(path, "/__bitbang__/"):
			name := strings.TrimPrefix(path, "/__bitbang__/")
			// No subpaths under __bitbang__; only flat filenames.
			if strings.ContainsRune(name, '/') || !allowedBitbangAssets[name] {
				http.NotFound(w, r)
				return
			}
			if name == "favicon.ico" {
				serveFile(w, r, staticDir, "favicon.png", "image/png", false)
				return
			}
			// Top-level .js files served with no-cache; sw.js gets the
			// Service-Worker-Allowed header so it can claim the root scope.
			noCache := true
			if name == "sw.js" {
				w.Header().Set("Service-Worker-Allowed", "/")
			}
			serveFile(w, r, staticDir, name, "", noCache)
			return
		}

		// /<uid> or /<uid>/<subpath>
		trimmed := strings.TrimPrefix(path, "/")
		if trimmed == "" {
			http.NotFound(w, r)
			return
		}
		first := trimmed
		if i := strings.IndexByte(trimmed, '/'); i >= 0 {
			first = trimmed[:i]
		}

		// Special case: /<file>.js at the top level — serve that JS file
		// (matches Python's "if uid.endswith('.js'): send_file(uid)" branch).
		if strings.HasSuffix(first, ".js") && !strings.ContainsAny(first, "/\\") && !strings.Contains(first, "..") {
			serveFile(w, r, staticDir, first, "", false)
			return
		}

		// Default: serve bootstrap.html (SPA routing). no-cache like the JS —
		// the page carries inline CSS, so a stale cached copy means stale
		// styling against fresh bootstrap.js.
		serveFile(w, r, staticDir, "bootstrap.html", "", true)
	}
}

// serveFile serves <staticDir>/<name>. The name is validated for traversal
// by filepath.Clean + a prefix check. If contentType is empty, Go's
// http.ServeFile sets it based on extension.
func serveFile(w http.ResponseWriter, r *http.Request, staticDir, name, contentType string, noCache bool) {
	clean := filepath.Clean(name)
	if clean != name || strings.HasPrefix(clean, "..") || strings.ContainsAny(clean, "\\") {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Join(staticDir, clean)
	// Defensive: ensure fullPath is still under staticDir after join.
	absStatic, err := filepath.Abs(staticDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	absFull, err := filepath.Abs(fullPath)
	if err != nil || !strings.HasPrefix(absFull, absStatic+string(filepath.Separator)) && absFull != absStatic {
		http.NotFound(w, r)
		return
	}

	if noCache {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeFile(w, r, fullPath)
}
