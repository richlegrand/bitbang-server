package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "camera", "0.1.0", "esp32s3"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "tables"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "empty"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "camera", "0.1.0", "esp32s3", "app.bin"), []byte("APP"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "tables", "ota_8mb.bin"), []byte("TABLE"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>setup"), 0o644))
	// A file beside the tree, which no path may reach.
	must(os.WriteFile(filepath.Join(filepath.Dir(dir), "secret"), []byte("no"), 0o644))

	h := Files("/firmware", dir, FirmwareCache)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	cases := []struct {
		path, body, cache string
		code              int
	}{
		{"/firmware/camera/0.1.0/esp32s3/app.bin", "APP", "public, max-age=31536000, immutable", 200},
		{"/firmware/tables/ota_8mb.bin", "TABLE", "no-cache", 200},
		{"/firmware/", "<p>setup", "public, max-age=31536000, immutable", 200},
		{"/firmware/camera/", "", "", 404},       // a directory, no index: not listed
		{"/firmware/empty", "", "", 404},         // a directory named without its slash
		{"/firmware/nope.bin", "", "", 404},
		{"/firmware/../secret", "", "", 404},     // cleaned to /secret, inside dir: absent
		{"/firmware/%2e%2e/secret", "", "", 404}, // the same, escaped
	}
	for _, c := range cases {
		rec := get(c.path)
		if rec.Code != c.code {
			t.Errorf("%s: status %d, want %d", c.path, rec.Code, c.code)
			continue
		}
		if c.code != 200 {
			continue
		}
		if rec.Body.String() != c.body {
			t.Errorf("%s: body %q, want %q", c.path, rec.Body.String(), c.body)
		}
		if got := rec.Header().Get("Cache-Control"); got != c.cache {
			t.Errorf("%s: Cache-Control %q, want %q", c.path, got, c.cache)
		}
	}

	if got := SetupCache("/app.js"); got != "no-cache" {
		t.Errorf("SetupCache: %q", got)
	}
}
