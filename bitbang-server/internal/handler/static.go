package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// frontPagePlaceholder is the literal marker bootstrap.html contains where
// an operator's snippet (set via FRONT_PAGE_PATH) is spliced when serving
// the entry page at `/`. The snippet should include a
// `<div id="bb-pair-input"></div>` somewhere; bootstrap.js's
// showPairingInput renders the pair-code form into it (or at the end of
// the snippet if the div is missing). When the env var is empty or the
// file can't be read, the placeholder is replaced with an empty string —
// the page degrades to the bare pair input.
const frontPagePlaceholder = "<!-- FRONT_PAGE -->"

// allowedBitbangAssets is the whitelist of files served at /__bitbang__/<file>.
// Anything else returns 404. A new browser-runtime asset has to be added here
// or it 404s at load time with no other symptom.
var allowedBitbangAssets = map[string]bool{
	"sw.js":         true,
	"bootstrap.js":  true,
	"ws-shim.js":    true,
	"xhr-shim.js":   true,
	"favicon.ico":   true, // handler internally maps this to favicon.png
}

// Static returns an http.Handler that serves the signaling server's static
// assets from staticDir. Routes:
//
//	GET /favicon.ico            -> favicon.png
//	GET /__bitbang__/<file>     -> whitelisted assets with no-cache headers
//	GET /                       -> bootstrap.html with FRONT_PAGE splice
//	GET /<uid>                  -> bootstrap.html (or <uid>.js if uid ends in .js)
//	GET /<uid>/<subpath>        -> bootstrap.html
//
// /status, /install, and /ws/... are routed elsewhere (this is the catch-all).
//
// frontPagePath, when non-empty, is the path to an HTML snippet read on
// every request to `/` and spliced into bootstrap.html at
// frontPagePlaceholder. Empty disables the splice; the placeholder is
// always replaced (with empty string if no snippet) so the marker never
// leaks to the browser.
func Static(staticDir, frontPagePath string) http.HandlerFunc {
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

		// /, /<uid>, /<uid>/<subpath>, or /<6-digit pair code> —
		// all fall through to bootstrap.html; the SPA router picks
		// the right state from the path.
		trimmed := strings.TrimPrefix(path, "/")
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

		// Entry page `/` gets the FRONT_PAGE splice — the only path that
		// renders the pair-input form is also the only one where an
		// operator's branding/install hint matters. Other bootstrap.html
		// serves (UID paths, 6-digit codes) skip the splice entirely.
		if path == "/" {
			serveBootstrapWithFrontPage(w, r, staticDir, frontPagePath)
			return
		}

		// Default: serve bootstrap.html (SPA routing). no-cache like the JS —
		// the page carries inline CSS, so a stale cached copy means stale
		// styling against fresh bootstrap.js.
		serveFile(w, r, staticDir, "bootstrap.html", "", true)
	}
}

// serveBootstrapWithFrontPage reads bootstrap.html and the front-page
// snippet on every request — files are tiny, IO is cheap, and operators
// can edit the snippet without a service restart. Both reads can fail
// independently: a missing snippet replaces the placeholder with empty
// string (and the page degrades to bare pair input); a missing or
// unreadable bootstrap.html is a 500.
func serveBootstrapWithFrontPage(w http.ResponseWriter, r *http.Request, staticDir, frontPagePath string) {
	html, err := os.ReadFile(filepath.Join(staticDir, "bootstrap.html"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var snippet []byte
	if frontPagePath != "" {
		// Best-effort: a misconfigured FRONT_PAGE_PATH shouldn't take the
		// entry page down. Log nothing here — the operator sees the
		// missing snippet in their browser the next time they visit.
		snippet, _ = os.ReadFile(frontPagePath)
	}
	out := strings.Replace(string(html), frontPagePlaceholder, string(snippet), 1)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
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
