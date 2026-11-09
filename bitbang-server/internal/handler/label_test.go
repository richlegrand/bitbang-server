package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLabelHost(t *testing.T) {
	cases := []struct {
		host   string
		parent string
		ok     bool
	}{
		{"abcdefghijklmnop.bitba.ng", "bitba.ng", true},
		{"abcdefghijklmnop.test.bitba.ng", "test.bitba.ng", true},
		{"abcdefghijklm234.bb.localhost:8800", "bb.localhost:8800", true},
		{"ABCDEFGHIJKLMNOP.bitba.ng", "bitba.ng", true}, // DNS is case-insensitive
		{"bitba.ng", "", false},
		{"test.bitba.ng", "", false},
		{"www.bitba.ng", "", false},
		{"abcdefghijklmno.bitba.ng", "", false},   // 15 characters
		{"abcdefghijklmnopq.bitba.ng", "", false}, // 17
		{"abcdefghijklmn01.bitba.ng", "", false},  // 0 and 1 are not base32
		{"abcdefghijklmnop", "", false},           // no parent
		{"abcdefghijklmnop.", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		parent, ok := LabelHost(c.host)
		if ok != c.ok || parent != c.parent {
			t.Errorf("LabelHost(%q) = %q, %v; want %q, %v", c.host, parent, ok, c.parent, c.ok)
		}
	}
}

func labelGet(t *testing.T, h http.Handler, method, host, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLabelServesOnlyItsOwnFiles(t *testing.T) {
	dir := stampDir(t)
	stamps := NewStampCache(dir, loadPlugins(t, dir).Files()...)
	h := Label(stamps, loadPlugins(t, dir))
	const host = "abcdefghijklmnop.test.bitba.ng"

	// Every response, whatever it is, may only be framed by the parent.
	check := func(path string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors test.bitba.ng" {
			t.Errorf("%s: CSP = %q", path, got)
		}
	}

	// The start page, at its own path and in place of any other.
	for _, path := range []string{"/__bb/start", "/", "/settings", "/x/y?z=1", "/ws/client/abc", "/status", "/install"} {
		rec := labelGet(t, h, http.MethodGet, host, path)
		check(path, rec)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<!-- start ") {
			t.Errorf("%s: want the start page, got %d %q", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), buildPlaceholder) {
			t.Errorf("%s: start page not stamped", path)
		}
	}

	// The worker, stamped, with the scope header.
	rec := labelGet(t, h, http.MethodGet, host, "/__bitbang__/label-sw.js")
	check("label-sw.js", rec)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), buildPlaceholder) {
		t.Errorf("label-sw.js: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Service-Worker-Allowed") != "/" {
		t.Errorf("label-sw.js: Service-Worker-Allowed = %q", rec.Header().Get("Service-Worker-Allowed"))
	}

	// What a device page loads, including a plugin's page.
	for _, name := range []string{"device-shim.js", "ws-shim.js", "stream-shim.js", "bitbang.js", "render-mjpeg.js", "settings.html", "console-panel.js"} {
		rec := labelGet(t, h, http.MethodGet, host, "/__bitbang__/"+name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}

	// Never the parent page's own runtime.
	for _, name := range []string{"sw.js", "bootstrap.js", "xhr-shim.js", "nope.js", "a/b.js"} {
		rec := labelGet(t, h, http.MethodGet, host, "/__bitbang__/"+name)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", name, rec.Code)
		}
	}

	// A post with no worker to take it gets the start page, not an error.
	rec = labelGet(t, h, http.MethodPost, host, "/login")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<!-- start ") {
		t.Errorf("POST /login: %d %q", rec.Code, rec.Body.String())
	}
}

func TestParentDoesNotServeLabelFiles(t *testing.T) {
	dir := stampDir(t)
	stamps := NewStampCache(dir)
	h := Static(stamps, "", nil)
	for _, name := range []string{"label-sw.js", "label-start.html", "device-shim.js"} {
		rec := labelGet(t, h, http.MethodGet, "test.bitba.ng", "/__bitbang__/"+name)
		if rec.Code != http.StatusNotFound {
			t.Errorf("parent served %s: %d", name, rec.Code)
		}
	}
}
