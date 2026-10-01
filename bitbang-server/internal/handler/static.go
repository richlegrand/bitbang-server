package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
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
	"stream-shim.js",
	// The loader a device page includes, which decides what else to fetch.
	"bitbang.js",
	// Temporary: leaves with settings.html when the config page becomes a plugin.
	"settings.html",
	// The panel settings.html mounts, and that a device page mounts too through
	// data-bitbang-page. Here because a stamp has to cover everything the browser
	// runtime is made of, and all of the settings rendering lives in this file
	// now: a change to it that did not move the stamp would leave every open tab
	// running the old copy.
	"settings-panel.js",
	"console.html",
	// The same for the console: console.html mounts it, and so does a device
	// page through data-bitbang-page="console".
	"console-panel.js",
	// Folding, and one setting's control, which both panels import.
	"panel-fold.js",
	"setting-control.js",
	"ota.html",
	// The renderers. Temporary in the same sense: they move to a plugin of
	// their own, which is not the one settings.html goes to -- a renderer is a
	// codec adapter, and a device sending mjpeg wants the mjpeg renderer
	// while wanting nothing to do with any particular device's firmware.
	"pcm-ring.js",
	"render-mjpeg.js",
	"render-ulaw.js",
}

// buildStamp hashes the on-disk bytes of every stamp input, with their
// placeholders still in place, so each stamped file receives an
// identical value. Names are hashed alongside contents so that moving
// bytes between files still moves the stamp.
//
// An unreadable file is folded in as a miss rather than being fatal --
// the stamp still changes if it later appears, and a server that boots is
// worth more than one that refuses over a shim.
//
// Reached through a StampCache rather than called per request: reading
// 400 KB to answer every asset request would be absurd, and calling it
// once at startup was wrong in a way nothing detected. See StampCache.
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

// How long a stamp is trusted before the inputs are looked at again.
//
// It bounds how long a deploy can go unnoticed, and the answer only
// matters to a browser that asks for an asset in that window -- so five
// seconds is already far below anything a person could perceive.
//
// A var so a test can retire a stamp without sleeping through it.
var stampMaxAge = 5 * time.Second

// StampCache answers "what is the current build" cheaply and correctly.
//
// The stamp used to be computed once, when the handler was built, on the
// reasoning that a deploy ships web/ and restarts the service so process
// lifetime and asset lifetime are the same thing. Where that holds it is
// true. Where it does not, the result is the worst available kind of
// wrong: serveStamped reads its bytes per request, so a web/ changed in
// place serves the new bootstrap.js carrying the old stamp, and serves an
// sw.js byte-identical to the one the browser already has. No worker
// installs, nothing turns over, and the page ends up running new code
// against an old worker with both halves agreeing they are the same
// build. reloadIfStale compares them, finds them equal, and does nothing.
// Nothing logs, and the only symptom is a stale service worker answering
// for sessions it no longer understands.
//
// Rechecked lazily, on a request, rather than by a ticker. Same latency
// for the same interval, and two things follow from it: a server nobody
// is asking does no work at all, and there is no goroutine to own or shut
// down. The cost is a monotonic clock read per request and one sweep per
// stampMaxAge however many requests arrive in it.
//
// The sweep stats; it rehashes only when a size or an mtime moved. Those
// two are what decides whether to look, never what the stamp is -- a
// deploy that rsyncs an unchanged file bumps its mtime, and a stamp built
// from mtimes would reload every open tab over a file whose bytes are the
// same. Contents decide the stamp; metadata only decides when to read
// them.
type StampCache struct {
	dir string

	mu      sync.Mutex
	stamp   string
	meta    string    // sizes and mtimes as of the last sweep
	checked time.Time // when that sweep happened
}

// NewStampCache is shared by the static handler, which splices the stamp into
// what it serves, and the client socket, which tells an open tab when the
// stamp has moved -- one cache, so the two can never disagree about which
// build is current.
func NewStampCache(dir string) *StampCache {
	c := &StampCache{dir: dir}
	c.stamp = buildStamp(dir)
	c.meta = c.readMeta()
	c.checked = time.Now()
	return c
}

// readMeta is the cheap half: one stat per input, formatted so that any
// change to a size, an mtime, or the set of readable files changes the
// string. Measured at 39us for the fourteen inputs.
func (c *StampCache) readMeta() string {
	var b strings.Builder
	for _, name := range stampInputs {
		fi, err := os.Stat(filepath.Join(c.dir, name))
		if err != nil {
			b.WriteString(name + ":-\n")
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d\n", name, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

func (c *StampCache) Current() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.checked) < stampMaxAge {
		return c.stamp
	}
	c.checked = time.Now()

	meta := c.readMeta()
	if meta == c.meta {
		return c.stamp
	}
	c.meta = meta

	/* A changed stamp is worth a line. It is the one event that reloads
	   every open tab, so when someone asks why their session restarted
	   this is the answer, with a timestamp. */
	next := buildStamp(c.dir)
	if next != c.stamp {
		log.Printf("build stamp %s -> %s (web/ changed under a running server)",
			c.stamp, next)
		c.stamp = next
	}
	return c.stamp
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
	// The one asset a device page names. Everything behind it can be renamed or
	// split; this cannot, because it is compiled into firmware.
	"bitbang.js":     true,
	"ws-shim.js":     true,
	"xhr-shim.js":    true,
	"stream-shim.js": true, // renders whatever a device streams, in its page
	"favicon.ico":    true, // handler internally maps this to favicon.png
	// Temporary: goes away when a plugin serves its own assets.
	"settings.html": true, // the device-settings meta-page shell
	// Mounted into a shadow root: by settings.html standalone, and through
	// bitbang.js when a device page carries data-bitbang-page="settings".
	"settings-panel.js": true,
	"console.html":      true, // the device-console meta-page shell
	// The same for the console, and data-bitbang-page="console".
	"console-panel.js":   true,
	"panel-fold.js":      true, // folding, imported by both panels
	"setting-control.js": true, // one setting's control, imported by both panels
	"ota.html":           true, // the device-firmware meta-page shell
	// The renderers, one per codec, fetched by the shim the first time a
	// channel announces that codec. Served here rather than embedded in a
	// device page, because rendering is a property of the codec and not of any
	// one device -- an ESP32, a Pi and a Python process sending mjpeg all want
	// this same file, and none of them should have to carry a copy.
	//
	// pcm-ring.js is a level below those: an AudioWorklet module, loaded by
	// render-ulaw.js rather than by the shim, and it needs a URL of its own
	// because addModule cannot take a string.
	"pcm-ring.js":     true,
	"render-mjpeg.js": true,
	"render-ulaw.js":  true,
}

// metaPageNames returns the meta-page names this server can serve, sorted --
// the .html entries above, without the extension, which is the spelling
// someone types after the '*' in /*settings.
//
// It is derived rather than declared so that adding a shell to the map above is
// the only step. sw.js used to keep its own copy of these three names and gate
// on it; that list refused nothing this one does not, and it was the copy that
// went stale when config.html was renamed. The service worker now asks for
// <name>.html and reports whatever comes back, so this is the only authority,
// and it is the one a plugin registering a page would extend.
func metaPageNames() []string {
	var out []string
	for name := range allowedBitbangAssets {
		if ext := strings.TrimSuffix(name, ".html"); ext != name {
			out = append(out, ext)
		}
	}
	sort.Strings(out)
	return out
}

// notFoundMetaPage answers a miss under /__bitbang__/<name>.html by naming what
// does exist. Guessing a plausible name is how someone finds out which pages
// are real, and a bare 404 sends them to read source instead.
func notFoundMetaPage(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "no meta-page named %q (have: %s)\n",
		name, strings.Join(metaPageNames(), ", "))
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
//
// The stamp cache is passed in rather than built here so the client socket can
// share it; see NewStampCache. The directory served is the cache's own.
func Static(stamps *StampCache, frontPagePath string) http.HandlerFunc {
	staticDir := stamps.dir
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
				// A miss on a .html here is someone asking for a meta-page
				// that does not exist -- /*foo in the address bar, resolved
				// by the service worker into foo.html. Worth naming the ones
				// that do, since this is the first error they meet. Every
				// other miss is a runtime asset and its own bug.
				if base, ok := strings.CutSuffix(name, ".html"); ok &&
					!strings.ContainsRune(name, '/') {
					notFoundMetaPage(w, base)
					return
				}
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
				serveStamped(w, staticDir, name, stamps.Current())
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

		// Special case: /<file>.js at the top level -- serve that JS file.
		// Inherited from the Python server and unexamined: nothing served
		// today asks for one (bootstrap.html and the service worker both use
		// /__bitbang__/), so it may only be here for pages older than that.
		if strings.HasSuffix(first, ".js") && !strings.ContainsAny(first, "/\\") && !strings.Contains(first, "..") {
			// no-cache like the /__bitbang__/ route. This branch served
			// cacheable until now, which meant the same asset had a stale
			// and a fresh spelling depending on which URL you asked for.
			if stampedAssets[first] {
				serveStamped(w, staticDir, first, stamps.Current())
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
