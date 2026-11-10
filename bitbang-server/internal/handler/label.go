package handler

// Device origins: each device's pages are served from an origin of its own,
// <label>.<host>, inside the bitba.ng page that holds the connection. See
// bitbang-docs/device-origins.md.
//
// The server's part is small, and never involves knowing which device a label
// belongs to -- it can't: the label is computed in the browser from a secret
// the server never sees. Every label host gets the same few files:
//
//   - the start page, at /__bb/start: the connection frame's document. It
//     installs the label worker, holds the device connection, and frames the
//     device's pages;
//   - the label worker and the runtime assets a device page loads from
//     /__bitbang__/ (the shims, bitbang.js, the renderers, the plugins'
//     pages and panels);
//   - for every other path, the start page again. A request that reaches the
//     server at all means no worker controls this origin yet, so the answer
//     is to install one, then load the same path through it.
//
// No signaling, no /status, no /<uid> pages: device content arrives over the
// data channel, never from here. The connection frame does open a signaling
// socket, to the parent host, but it never holds the access code -- bitba.ng's
// page keeps that and hands down only a proof for each connection.
//
// A label host is only ever framed: a top-level load (a link opened in a new
// tab, a page busting out of its frame) gets a page saying to open the device
// from its bitba.ng link, since nothing here knows which device that was.

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// labelRE is one label as the browser computes it: 16 characters of
// lowercase base32 (10 bytes of an HMAC). Anything else is not a label host,
// so a self-hoster's own subdomains are untouched.
var labelRE = regexp.MustCompile(`^[a-z2-7]{16}$`)

// LabelHost reports whether host -- a Host header, port and all -- names a
// device origin: a label, then the host this server answers as. It returns
// that parent host, port included, which is the only origin allowed to frame
// a label page.
func LabelHost(host string) (parent string, ok bool) {
	name, port := host, ""
	if h, p, err := net.SplitHostPort(host); err == nil {
		name, port = h, p
	}
	label, rest, found := strings.Cut(strings.ToLower(name), ".")
	if !found || rest == "" || !labelRE.MatchString(label) {
		return "", false
	}
	if port != "" {
		rest = net.JoinHostPort(rest, port)
	}
	return rest, true
}

// labelAssets are what a label host serves at /__bitbang__/<name>, besides the
// plugins' files. Not sw.js or bootstrap.js: those are bitba.ng's own page,
// which keeps the access code. The label origin gets the connection half
// only, which has nothing to connect with until that page sends a proof.
var labelAssets = map[string]bool{
	"label-sw.js":        true, // the label worker; root scope via the header below
	"device-shim.js":     true, // injected into every device page
	"ws-shim.js":         true,
	"stream-shim.js":     true,
	"bitbang.js":         true, // compiled into firmware; this name cannot change
	"panel-fold.js":      true,
	"setting-control.js": true,
	"pcm-ring.js":        true,
	"render-mjpeg.js":    true,
	"render-ulaw.js":     true,
}

// labelStartPage is the start page's file, and labelStartPath where a label
// origin's iframe always enters.
const (
	labelStartPage = "label-start.html"
	labelStartPath = "/__bb/start"
)

// Label serves a label host. main.go routes a request here when LabelHost says
// its Host is one, ahead of every other route.
func Label(stamps *StampCache, plugins PluginFiles) http.HandlerFunc {
	staticDir := stamps.dir
	return func(w http.ResponseWriter, r *http.Request) {
		parent, ok := LabelHost(r.Host)
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Only the parent may frame anything here, with the label origin
		// itself in between: frame-ancestors is checked against every
		// ancestor, and a device page's are the connection frame (this
		// origin) and bitba.ng. A page framed by another site is someone's
		// attempt to borrow a bitba.ng name. A host-source with no scheme
		// matches the scheme of this response, so the same line serves http
		// on a laptop and https in production.
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self' "+parent)
		w.Header().Set("Referrer-Policy", "same-origin")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// A form posted to a label origin with no worker. Answer with the
			// start page as a GET would; the post itself is lost, as it would
			// be against any server that is not there.
			serveLabelStart(w, r, staticDir, stamps)
			return
		}

		// A top-level document: a link opened in a new tab, a frame-busting
		// page. Browsers that send Sec-Fetch-Dest say so; the start page
		// checks again for those that don't.
		if r.Header.Get("Sec-Fetch-Dest") == "document" {
			serveLabelTopLevel(w, parent)
			return
		}

		path := r.URL.Path
		if name, isAsset := strings.CutPrefix(path, "/__bitbang__/"); isAsset {
			if strings.ContainsRune(name, '/') {
				http.NotFound(w, r)
				return
			}
			if !labelAssets[name] {
				if plugins != nil {
					if rel, ok := plugins.File(name); ok {
						serveFile(w, r, staticDir, rel, "", true)
						return
					}
				}
				http.NotFound(w, r)
				return
			}
			if name == "label-sw.js" {
				// Served from /__bitbang__/ but controls the whole origin.
				w.Header().Set("Service-Worker-Allowed", "/")
			}
			if stampedAssets[name] {
				serveStamped(w, staticDir, name, stamps.Current())
				return
			}
			serveFile(w, r, staticDir, name, "", true)
			return
		}

		// /__bb/start, and every path a worker would have answered had there
		// been one.
		serveLabelStart(w, r, staticDir, stamps)
	}
}

// serveLabelTopLevel answers a label URL loaded outside its frame. The page
// can't send the user back where they were: it has no uid and no code, by
// design. It links to the parent's front page, nothing more.
func serveLabelTopLevel(w http.ResponseWriter, parent string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, labelTopLevelPage, html.EscapeString(parent))
}

// labelTopLevelPage is served for a top-level load. "<!-- top-level -->" is
// how tests tell it from the start page.
const labelTopLevelPage = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Open from your link - BitBang</title>
<!-- top-level -->
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32em;margin:3em auto;padding:0 16px}</style>
<p>This page only works inside the BitBang tab it came from.</p>
<p>Go back to that tab, or open the device again from its link.</p>
<p><a href="//%s/">BitBang</a></p>
`

// serveLabelStart serves the start page, stamped, uncached: a stale one would
// install a stale worker.
func serveLabelStart(w http.ResponseWriter, r *http.Request, staticDir string, stamps *StampCache) {
	serveStampedAs(w, staticDir, labelStartPage, stamps.Current(), "text/html; charset=utf-8")
}
