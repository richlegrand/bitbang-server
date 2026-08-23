package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stampDir writes a minimal web/ whose stamped assets carry the
// placeholder, so a test can serve them for real.
func stampDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"bootstrap.html": "<html><!-- FRONT_PAGE --></html>",
		"bootstrap.js":   "const BUILD = '" + buildPlaceholder + "';\n",
		"sw.js":          "const BUILD = '" + buildPlaceholder + "';\n",
		"ws-shim.js":     "// ws shim\n",
		"xhr-shim.js":    "// xhr shim\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func serveAsset(t *testing.T, dir, path string) *httptest.ResponseRecorder {
	t.Helper()
	h := Static(dir, "")
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
// makes a shim-only deploy visible to an open tab.
func TestEveryRuntimeAssetMovesTheStamp(t *testing.T) {
	for _, name := range stampInputs {
		t.Run(name, func(t *testing.T) {
			dir := stampDir(t)
			before := buildStamp(dir)

			path := filepath.Join(dir, name)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}

			if after := buildStamp(dir); after == before {
				t.Errorf("editing %s left the stamp at %s", name, before)
			}
		})
	}
}

// favicon is excluded on purpose: it is served cacheable and nothing
// depends on its version, so it must not reload every open tab.
func TestFaviconDoesNotMoveTheStamp(t *testing.T) {
	dir := stampDir(t)
	before := buildStamp(dir)
	if err := os.WriteFile(filepath.Join(dir, "favicon.png"), []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	if after := buildStamp(dir); after != before {
		t.Error("a favicon change reloaded every tab")
	}
}

// A missing asset must not stop the server from starting, and must not
// look like an unchanged one either.
func TestStampSurvivesAMissingAsset(t *testing.T) {
	dir := stampDir(t)
	full := buildStamp(dir)
	if err := os.Remove(filepath.Join(dir, "ws-shim.js")); err != nil {
		t.Fatal(err)
	}
	partial := buildStamp(dir)
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
