package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"bitbang-server-go/internal/plugin"
	"bitbang-server-go/internal/plugins/console"
	"bitbang-server-go/internal/plugins/ota"
	"bitbang-server-go/internal/plugins/settings"
)

// loadPlugins loads the plugins main.go does, against dir, and fails the test
// if any is down -- a fixture missing a plugin's file would otherwise show up
// as a confusing 404 several assertions later.
func loadPlugins(t *testing.T, dir string) *plugin.Registry {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := plugin.Load(dir, log, IsCoreAsset,
		settings.Plugin{}, console.Plugin{}, ota.Plugin{})
	for _, st := range reg.Status() {
		if !st.Up {
			t.Fatalf("plugin %s is down: %s", st.Name, st.Error)
		}
	}
	return reg
}

// stampDir writes a minimal web/ whose stamped assets carry the
// placeholder, so a test can serve them for real.
func stampDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"bootstrap.html":     "<html><!-- FRONT_PAGE --></html>",
		"bootstrap.js":       "const BUILD = '" + buildPlaceholder + "';\n",
		"sw.js":              "const BUILD = '" + buildPlaceholder + "';\n",
		"ws-shim.js":         "// ws shim\n",
		"xhr-shim.js":        "// xhr shim\n",
		"stream-shim.js":     "// stream shim\n",
		"bitbang.js":         "// loader\n",
		"panel-fold.js":      "// panel fold\n",
		"setting-control.js": "// setting control\n",
		"pcm-ring.js":        "// pcm ring\n",
		"render-mjpeg.js":    "// mjpeg\n",
		"render-ulaw.js":     "// ulaw\n",
		// The plugins', each in its own directory.
		"plugins/settings/settings.html":     "<html><!-- settings --></html>",
		"plugins/settings/settings-panel.js": "// settings panel\n",
		"plugins/console/console.html":       "<html><!-- console --></html>",
		"plugins/console/console-panel.js":   "// console panel\n",
		"plugins/ota/ota.html":               "<html><!-- firmware --></html>",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func serveAsset(t *testing.T, dir, path string) *httptest.ResponseRecorder {
	t.Helper()
	reg := loadPlugins(t, dir)
	h := Static(NewStampCache(dir, reg.Files()...), "", reg)
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// The failure this exists for: if the splice silently stops happening,
// every page reports the literal placeholder, they all agree with each
// other, and nothing ever reloads. It fails closed and quiet, which is
// indistinguishable from working.
func TestStampedAssetsCarryNoPlaceholder(t *testing.T) {
	dir := stampDir(t)
	for _, path := range []string{
		"/__bitbang__/bootstrap.js",
		"/__bitbang__/sw.js",
		"/bootstrap.js", // the legacy top-level route stamps too
	} {
		t.Run(path, func(t *testing.T) {
			body := serveAsset(t, dir, path).Body.String()
			if strings.Contains(body, buildPlaceholder) {
				t.Fatalf("%s still contains %s -- the splice did not run", path, buildPlaceholder)
			}
			if !strings.Contains(body, "const BUILD = '") {
				t.Fatalf("%s lost its BUILD line entirely: %q", path, body)
			}
		})
	}
}

// Both files must report the same value or a current page would think
// itself stale and reload on every load.
func TestStampIsIdenticalAcrossAssets(t *testing.T) {
	dir := stampDir(t)
	js := serveAsset(t, dir, "/__bitbang__/bootstrap.js").Body.String()
	sw := serveAsset(t, dir, "/__bitbang__/sw.js").Body.String()
	if js != sw {
		t.Errorf("bootstrap.js %q != sw.js %q", js, sw)
	}
	if strings.TrimSpace(js) == "const BUILD = '';" {
		t.Error("stamp is empty")
	}
}

// A change to any runtime asset has to move the stamp -- that is what
// makes a shim-only deploy visible to an open tab. A plugin's files included:
// they are the runtime as much as the core's are.
func TestEveryRuntimeAssetMovesTheStamp(t *testing.T) {
	inputs := NewStampCache(stampDir(t), loadPlugins(t, stampDir(t)).Files()...).inputs
	if len(inputs) == len(stampInputs) {
		t.Fatal("no plugin files among the stamp inputs")
	}
	for _, name := range inputs {
		t.Run(name, func(t *testing.T) {
			dir := stampDir(t)
			before := buildStamp(dir, inputs)

			path := filepath.Join(dir, name)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}

			if after := buildStamp(dir, inputs); after == before {
				t.Errorf("editing %s left the stamp at %s", name, before)
			}
		})
	}
}

// favicon is excluded on purpose: it is served cacheable and nothing
// depends on its version, so it must not reload every open tab.
func TestFaviconDoesNotMoveTheStamp(t *testing.T) {
	dir := stampDir(t)
	before := buildStamp(dir, stampInputs)
	if err := os.WriteFile(filepath.Join(dir, "favicon.png"), []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	if after := buildStamp(dir, stampInputs); after != before {
		t.Error("a favicon change reloaded every tab")
	}
}

// A missing asset must not stop the server from starting, and must not
// look like an unchanged one either.
func TestStampSurvivesAMissingAsset(t *testing.T) {
	dir := stampDir(t)
	full := buildStamp(dir, stampInputs)
	if err := os.Remove(filepath.Join(dir, "ws-shim.js")); err != nil {
		t.Fatal(err)
	}
	partial := buildStamp(dir, stampInputs)
	if partial == "" {
		t.Fatal("no stamp at all with one asset missing")
	}
	if partial == full {
		t.Error("a missing asset produced the same stamp as a present one")
	}
}

// Everything under /__bitbang__/ and the legacy route is no-store, or a
// browser could hold a stale copy of the very file that reports staleness.
func TestStampedAssetsAreNotCacheable(t *testing.T) {
	dir := stampDir(t)
	for _, path := range []string{
		"/__bitbang__/bootstrap.js",
		"/__bitbang__/sw.js",
		"/__bitbang__/ws-shim.js",
		"/bootstrap.js",
	} {
		got := serveAsset(t, dir, path).Header().Get("Cache-Control")
		if !strings.Contains(got, "no-store") {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}
}

// Every asset the service worker injects into a device page has to be
// servable, and every servable asset has to exist.
//
// This is the failure it exists for, and it has happened: a new shim is added,
// its <script src> goes into sw.js, and allowedBitbangAssets is not updated.
// The tag 404s inside an iframe, nothing renders, and there is no error
// anywhere a person is looking. The same for a name in the whitelist whose
// file was never added or was later renamed.
//
// Reads the real web/ rather than a fixture, because a fixture would agree
// with whatever the test itself wrote.
func TestInjectedScriptsAreServable(t *testing.T) {
	web := filepath.Join("..", "..", "web")
	sw, err := os.ReadFile(filepath.Join(web, "sw.js"))
	if err != nil {
		t.Skipf("no web/ beside the package: %v", err)
	}

	re := regexp.MustCompile(`<script src=\\?"/__bitbang__/([^"\\]+)`)
	found := re.FindAllStringSubmatch(string(sw), -1)
	if len(found) == 0 {
		t.Fatal("no injected /__bitbang__/ script tags found in sw.js -- " +
			"either the injection moved or this pattern stopped matching it")
	}
	for _, m := range found {
		name := m[1]
		if !allowedBitbangAssets[name] {
			t.Errorf("sw.js injects %s, which allowedBitbangAssets does not serve: "+
				"it will 404 inside the device page", name)
		}
	}

	for name := range allowedBitbangAssets {
		if name == "favicon.ico" {
			continue // served from favicon.png
		}
		if _, err := os.Stat(filepath.Join(web, name)); err != nil {
			t.Errorf("allowedBitbangAssets has %s, but web/ does not: %v", name, err)
		}
	}
}

// Every plugin main.go loads comes up against the real web/: each file it
// registers is where it says, and none collides with the core or another
// plugin. The plugin host checks all of that at startup and takes a failing
// plugin down -- which in production is a page that 404s with only a /status
// line to say why. Here it is a test failure instead.
func TestEveryPluginLoadsAgainstTheRealWeb(t *testing.T) {
	web := filepath.Join("..", "..", "web")
	if _, err := os.Stat(filepath.Join(web, "sw.js")); err != nil {
		t.Skipf("no web/ beside the package: %v", err)
	}
	loadPlugins(t, web)
}

// The meta-page shell has to be reachable at /__bitbang__/settings.html or the
// service worker's meta-page route returns 502 and the settings page is blank
// with nothing in the log. The shells are plugins' now, served from
// plugins/<name>/ at the same flat URL, and this is what says the plugin route
// is wired up.
func TestMetaPageShellIsServed(t *testing.T) {
	dir := stampDir(t)
	w := serveAsset(t, dir, "/__bitbang__/settings.html")
	if w.Code != http.StatusOK {
		t.Fatalf("settings.html: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("settings.html content type = %q, want text/html", ct)
	}
	// A plugin's shell, served from plugins/console/ at the same flat URL.
	if w := serveAsset(t, dir, "/__bitbang__/console.html"); w.Code != http.StatusOK {
		t.Fatalf("console.html: got %d, want 200", w.Code)
	} else if !strings.Contains(w.Body.String(), "console") {
		t.Errorf("console.html served the wrong file: %q", w.Body.String())
	}
	if w := serveAsset(t, dir, "/__bitbang__/console-panel.js"); w.Code != http.StatusOK {
		t.Fatalf("console-panel.js: got %d, want 200", w.Code)
	}
	// Not in the whitelist. This is now the only thing that refuses it: sw.js
	// used to keep its own copy of the meta-page names and check first, and that
	// copy is what went stale when config.html was renamed.
	if w := serveAsset(t, dir, "/__bitbang__/nope.html"); w.Code != http.StatusNotFound {
		t.Errorf("nope.html: got %d, want 404", w.Code)
	}
}

// The 404 for an unknown meta-page names the ones that exist, because that error
// is what someone who typed /*setings meets first, and the service worker passes
// this body through verbatim -- it no longer knows the names itself.
//
// Derived from allowedBitbangAssets rather than written out, so adding a shell
// to that map is the only step. A second list kept by hand is what this replaced.
func TestUnknownMetaPageNamesTheRealOnes(t *testing.T) {
	dir := stampDir(t)
	w := serveAsset(t, dir, "/__bitbang__/setings.html")
	if w.Code != http.StatusNotFound {
		t.Fatalf("setings.html: got %d, want 404", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"setings"`) {
		t.Errorf("404 body does not quote the name asked for: %q", body)
	}
	names := metaPageNames(loadPlugins(t, dir))
	if !contains(names, "console") {
		t.Errorf("the console plugin's page is missing from %v", names)
	}
	for _, want := range names {
		if !strings.Contains(body, want) {
			t.Errorf("404 body does not mention %q, which is servable: %q", want, body)
		}
	}
	// The names are the spelling that goes after the '*', so no extension.
	if strings.Contains(body, ".html") {
		t.Errorf("404 body offers filenames rather than meta-page names: %q", body)
	}

	// A miss that is not a meta-page stays an ordinary 404. Naming the shells
	// there would answer a question nobody asked: a missing shim is its own bug,
	// and TestInjectedScriptsAreServable is what catches it.
	if w := serveAsset(t, dir, "/__bitbang__/nope.js"); w.Code != http.StatusNotFound {
		t.Errorf("nope.js: got %d, want 404", w.Code)
	} else if strings.Contains(w.Body.String(), "meta-page") {
		t.Errorf("a missing .js was answered as a meta-page: %q", w.Body.String())
	}
}

// metaPageNames has to agree with what sw.js will ask for. The worker builds the
// filename by appending .html to the name in the URL, so every servable shell
// must be exactly <name>.html -- anything else is a page reachable by no URL, or
// a name in this list that resolves to nothing.
func TestMetaPageNamesRoundTripThroughTheWorkersRule(t *testing.T) {
	reg := loadPlugins(t, stampDir(t))
	names := metaPageNames(reg)
	if len(names) == 0 {
		t.Fatal("no meta-page shells in allowedBitbangAssets or the plugins")
	}
	for _, n := range names {
		_, fromPlugin := reg.File(n + ".html")
		if !allowedBitbangAssets[n+".html"] && !fromPlugin {
			t.Errorf("metaPageNames has %q but %s.html is not servable", n, n)
		}
		// The URL pattern in sw.js is [A-Za-z0-9_-]+. A name outside it is
		// unreachable however the server feels about it.
		for _, c := range n {
			ok := c == '-' || c == '_' ||
				(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !ok {
				t.Errorf("meta-page %q contains %q, which the service worker's "+
					"URL pattern will not match", n, c)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// -- a web/ that changes under a running server ----------------------------

// recheckEveryTime retires the stamp on every request for the duration of
// one test, so a test about what happens after the window does not have to
// sleep through the window.
func recheckEveryTime(t *testing.T) {
	t.Helper()
	was := stampMaxAge
	stampMaxAge = 0
	t.Cleanup(func() { stampMaxAge = was })
}

// stampOf serves sw.js through one handler and returns the spliced value,
// so a test can ask the same handler twice and see whether it moved.
func stampOf(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/__bitbang__/sw.js", nil)
	w := httptest.NewRecorder()
	h(w, r)
	m := regexp.MustCompile(`BUILD = '([^']*)'`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no stamp in sw.js: %q", w.Body.String())
	}
	return m[1]
}

// The defect this exists for, and it is worth stating plainly because
// nothing else in the system would have noticed it.
//
// The stamp used to be taken once, when the handler was built. Asset bytes
// are read per request. So a web/ that changed without the process
// restarting served the new bootstrap.js carrying the old stamp, and an
// sw.js byte-identical to the one the browser already had -- no worker
// installed, nothing turned over, and the page ran new code against an old
// worker with both halves agreeing on the build. reloadIfStale compared
// them, found them equal, and did nothing.
func TestStampFollowsAChangeUnderARunningHandler(t *testing.T) {
	recheckEveryTime(t)
	dir := stampDir(t)
	h := Static(NewStampCache(dir), "", nil)

	before := stampOf(t, h)

	// A shim changes, which is the case that carries no stamp of its own
	// and so relies entirely on this.
	if err := os.WriteFile(filepath.Join(dir, "xhr-shim.js"),
		[]byte("// xhr shim, revised\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if after := stampOf(t, h); after == before {
		t.Fatalf("stamp stayed %s after web/ changed", before)
	}
}

// And the other half of the same decision: metadata says when to look at
// the contents, never what the stamp is. A deploy that copies an unchanged
// file still bumps its mtime, and a stamp built from mtimes would reload
// every open tab over bytes that did not move.
func TestStampIgnoresATouchThatChangedNothing(t *testing.T) {
	recheckEveryTime(t)
	dir := stampDir(t)
	h := Static(NewStampCache(dir), "", nil)

	before := stampOf(t, h)

	// Moved by an hour rather than rewritten, so the mtime definitely
	// differs and the contents definitely do not -- which forces the path
	// where the sweep decides to rehash and the hash says nothing changed.
	path := filepath.Join(dir, "xhr-shim.js")
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	if after := stampOf(t, h); after != before {
		t.Fatalf("stamp moved %s -> %s over a touch that changed no bytes",
			before, after)
	}
}
