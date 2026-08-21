package handler

import (
	"crypto/sha256"
	"encoding/hex"
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

// buildPlaceholder is the literal marker bootstrap.js and sw.js contain
// where the build stamp is spliced in as they are served.
//
// The stamp is how a page works out whether it is still current. Both
// files get the same value, so a page whose copy disagrees with the
// active service worker's is by definition running older code -- which
// only happens to a tab that has been open across a deploy, since the
// assets are served no-store and any fresh navigation gets both anew.
const buildPlaceholder = "__BB_BUILD__"

// stampedAssets are the files the build stamp is spliced into. Serving
// them means reading and rewriting rather than handing off to
// http.ServeFile; they are a few tens of KB, and already served
// no-store, so nothing is lost.
var stampedAssets = map[string]bool{
	"bootstrap.js": true,
	"sw.js":        true,
}

// stampInputs are the files whose contents define a build. Every asset
// the browser runtime is made of belongs here, not just the two that
// carry the stamp: a deploy that changed only a shim would otherwise
// leave the stamp still and every open tab holding stale code -- which
// is the whole failure this exists to catch.
//
// favicon.png is left out deliberately. It is served cacheable, nothing
// depends on its version, and reloading everyone's tab over an icon is
// not a trade worth making.
var stampInputs = []string{
	"bootstrap.html",
	"bootstrap.js",
	"sw.js",
	"ws-shim.js",
	"xhr-shim.js",
}

// buildStamp hashes the on-disk bytes of every stamp input, with their
// placeholders still in place, so each stamped file receives an
// identical value. Names are hashed alongside contents so that moving
// bytes between files still moves the stamp.
//
// Computed once when the handler is built: a deploy ships web/ and
// restarts the service, so process lifetime and asset lifetime are the
// same thing. An unreadable file is folded in as a miss rather than
// being fatal -- the stamp still changes if it later appears, and a
// server that boots is worth more than one that refuses over a shim.
func buildStamp(staticDir string) string {
	h := sha256.New()
	for _, name := range stampInputs {
		h.Write([]byte(name))
		b, err := os.ReadFile(filepath.Join(staticDir, name))
		if err != nil {
			h.Write([]byte("<unreadable>"))
			continue
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// serveStamped writes a stamped asset with the build value spliced in.
func serveStamped(w http.ResponseWriter, staticDir, name, stamp string) {
	b, err := os.ReadFile(filepath.Join(staticDir, name))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := strings.Replace(string(b), buildPlaceholder, stamp, 1)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// allowedBitbangAssets is the whitelist of files served at /__bitbang__/<file>.
// Anything else returns 404. A new browser-runtime asset has to be added here
// or it 404s at load time with no other symptom.
var allowedBitbangAssets = map[string]bool{
	"sw.js":        true,
	"bootstrap.js": true,
	"ws-shim.js":   true,
	"xhr-shim.js":  true,
	"favicon.ico":  true, // handler internally maps this to favicon.png
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
	stamp := buildStamp(staticDir)
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
			if name == "sw.js" {
				w.Header().Set("Service-Worker-Allowed", "/")
			}
			if stampedAssets[name] {
				serveStamped(w, staticDir, name, stamp)
				return
			}
			serveFile(w, r, staticDir, name, "", true)
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
			// no-cache like the /__bitbang__/ route. This branch served
			// cacheable until now, which meant the same asset had a stale
			// and a fresh spelling depending on which URL you asked for.
			if stampedAssets[first] {
				serveStamped(w, staticDir, first, stamp)
				return
			}
			serveFile(w, r, staticDir, first, "", true)
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
