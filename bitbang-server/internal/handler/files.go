package handler

import (
	"net/http"
	"strings"
)

// Files serves the regular files under dir at the request path with prefix
// taken off, and nothing else: a directory is 404 unless it has an
// index.html, and is never listed. http.Dir keeps the path inside dir.
//
// cacheControl gives the Cache-Control header for a file's path (relative to
// dir, with a leading slash), so a caller can say which files never change.
//
// For trees the server serves but doesn't own: the web installer's page
// (/setup/), put in place by the deploy from its own repository, and the
// firmware images the installer writes (/firmware/), uploaded beside the
// server and kept across deploys.
func Files(prefix, dir string, cacheControl func(path string) string) http.Handler {
	root := http.Dir(dir)
	return http.StripPrefix(prefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "" || strings.HasSuffix(p, "/") {
			p += "index.html"
		}
		f, err := root.Open(p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", cacheControl(p))
		http.ServeContent(w, r, st.Name(), st.ModTime(), f)
	}))
}

// SetupCache is the installer page's: revalidated on every load, so a deploy
// reaches the next visitor, but answered 304 when nothing changed.
func SetupCache(string) string { return "no-cache" }

// FirmwareCache is the firmware tree's. An image lives at a path with its
// version in it and never changes there, so it is cached for good; the
// partition tables, named only by their layout, are revalidated.
func FirmwareCache(p string) string {
	if strings.HasPrefix(p, "/tables/") {
		return "no-cache"
	}
	return "public, max-age=31536000, immutable"
}
