package plugin

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fake is a plugin's code whose Init is whatever the test says.
type fake struct {
	name string
	init func(Host) error
}

func (f fake) Name() string      { return f.name }
func (f fake) Init(h Host) error { return f.init(h) }

func quiet() *slog.Logger      { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func noneReserved(string) bool { return false }

// web writes files under dir/plugins/ -- "con/plugin.json" and so on -- and
// returns dir, the static directory.
func web(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range files {
		path := filepath.Join(dir, "plugins", f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func statusOf(t *testing.T, r *Registry, name string) Status {
	t.Helper()
	for _, st := range r.Status() {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no status line for %s in %+v", name, r.Status())
	return Status{}
}

// A plugin with no code is a directory: its manifest names a meta-page and a
// panel, and they land at their flat names, from the plugin's own directory,
// counting toward the stamp.
func TestADirectoryIsAPlugin(t *testing.T) {
	dir := web(t, map[string]string{
		"con/plugin.json":  `{"meta_pages": ["con"], "panels": ["con"]}`,
		"con/con.html":     "page",
		"con/con-panel.js": "panel",
	})
	r := Discover(dir, quiet(), noneReserved, nil)

	if st := statusOf(t, r, "con"); !st.Up {
		t.Fatalf("down: %+v", st)
	}
	if rel, ok := r.File("con.html"); !ok || rel != filepath.Join("plugins", "con", "con.html") {
		t.Errorf("con.html -> %q, %v", rel, ok)
	}
	if !reflect.DeepEqual(r.MetaPages(), []string{"con"}) || !reflect.DeepEqual(r.Panels(), []string{"con"}) {
		t.Errorf("MetaPages = %v, Panels = %v", r.MetaPages(), r.Panels())
	}
	want := []string{filepath.Join("plugins", "con", "con-panel.js"), filepath.Join("plugins", "con", "con.html")}
	if !reflect.DeepEqual(r.Files(), want) {
		t.Errorf("Files = %v, want %v", r.Files(), want)
	}
	// The manifest is what makes it a plugin, not something to serve.
	if _, ok := r.File("plugin.json"); ok {
		t.Error("plugin.json is served")
	}
}

// A plugin with code: its manifest and its Init both register, through the
// same host.
func TestAPluginsCodeRunsBesideItsManifest(t *testing.T) {
	dir := web(t, map[string]string{
		"tg/plugin.json": `{"meta_pages": ["tg"]}`,
		"tg/tg.html":     "page",
		"tg/extra.js":    "module",
		"tg/tg.go":       "package tg",
	})
	ran := false
	code := []Plugin{fake{"tg", func(h Host) error { ran = true; return h.File("extra.js") }}}
	r := Discover(dir, quiet(), noneReserved, code)

	if st := statusOf(t, r, "tg"); !st.Up || !ran {
		t.Fatalf("status %+v, Init ran: %v", st, ran)
	}
	if _, ok := r.File("extra.js"); !ok {
		t.Error("the file Init registered is not served")
	}
}

// Go files whose code isn't in the binary: someone added a plugin and didn't
// regenerate. Down, and the error says what to run.
func TestCodeThatIsNotCompiledInIsReported(t *testing.T) {
	dir := web(t, map[string]string{
		"tg/plugin.json": `{"meta_pages": ["tg"]}`,
		"tg/tg.html":     "page",
		"tg/tg.go":       "package tg",
	})
	r := Discover(dir, quiet(), noneReserved, nil)
	st := statusOf(t, r, "tg")
	if st.Up || !strings.Contains(st.Error, "go generate") {
		t.Fatalf("status = %+v, want down naming go generate", st)
	}
	if len(r.Files()) != 0 {
		t.Errorf("serves %v anyway", r.Files())
	}
}

// Compiled in but not deployed is a deployment's choice: off, and not a
// failure on /status.
func TestCodeWithNoDirectoryIsOff(t *testing.T) {
	ran := false
	code := []Plugin{fake{"tg", func(Host) error { ran = true; return nil }}}
	r := Discover(web(t, nil), quiet(), noneReserved, code)
	if ran || len(r.Status()) != 0 {
		t.Fatalf("Init ran: %v, status %+v", ran, r.Status())
	}
}

// The failures it exists to turn from a silent 404 into a /status line. In
// each, the plugin is down and serves nothing -- including what it registered
// before the failure.
func TestAFailingPluginServesNothing(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		res   func(string) bool
		code  []Plugin
	}{
		{"no manifest", map[string]string{"p/p.html": "page"}, noneReserved, nil},
		{"a manifest that doesn't parse", map[string]string{"p/plugin.json": `{"meta_pages": [`}, noneReserved, nil},
		{"a misspelled key", map[string]string{"p/plugin.json": `{"meta_page": ["p"]}`, "p/p.html": ""}, noneReserved, nil},
		{"a missing file", map[string]string{"p/plugin.json": `{"meta_pages": ["p"]}`}, noneReserved, nil},
		{"a core name", map[string]string{"p/plugin.json": `{"files": ["sw.js"]}`, "p/sw.js": ""},
			func(s string) bool { return s == "sw.js" }, nil},
		{"a path, not a name", map[string]string{"p/plugin.json": `{"files": ["a/b.js"]}`, "p/a/b.js": ""}, noneReserved, nil},
		{"serving its own code", map[string]string{"p/plugin.json": `{"files": ["p.go"]}`, "p/p.go": ""},
			noneReserved, []Plugin{fake{"p", func(Host) error { return nil }}}},
		{"Init's error, after the manifest registered", map[string]string{"p/plugin.json": `{"meta_pages": ["p"]}`, "p/p.html": "", "p/p.go": ""},
			noneReserved, []Plugin{fake{"p", func(Host) error { return errors.New("not today") }}}},
		{"a panic in Init", map[string]string{"p/plugin.json": `{"meta_pages": ["p"]}`, "p/p.html": "", "p/p.go": ""},
			noneReserved, []Plugin{fake{"p", func(Host) error { panic("boom") }}}},
		{"two packages with one name", map[string]string{"p/plugin.json": `{}`, "p/p.go": ""},
			noneReserved, []Plugin{fake{"p", func(Host) error { return nil }}, fake{"p", func(Host) error { return nil }}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Discover(web(t, c.files), quiet(), c.res, c.code)
			st := statusOf(t, r, "p")
			if st.Up || st.Error == "" {
				t.Fatalf("status = %+v, want down with a reason", st)
			}
			if len(r.Files()) != 0 || len(r.MetaPages()) != 0 {
				t.Errorf("a down plugin still serves %v / %v", r.Files(), r.MetaPages())
			}
		})
	}
}

// Two plugins claiming one name: the first in directory order keeps it, the
// second is down, and the rest still load.
func TestASecondClaimToANameIsRefused(t *testing.T) {
	dir := web(t, map[string]string{
		"a/plugin.json": `{"meta_pages": ["x"]}`, "a/x.html": "a",
		"b/plugin.json": `{"meta_pages": ["x"]}`, "b/x.html": "b",
		"c/plugin.json": `{"meta_pages": ["c"]}`, "c/c.html": "c",
	})
	r := Discover(dir, quiet(), noneReserved, nil)
	if !statusOf(t, r, "a").Up || statusOf(t, r, "b").Up || !statusOf(t, r, "c").Up {
		t.Fatalf("status = %+v", r.Status())
	}
	if rel, _ := r.File("x.html"); rel != filepath.Join("plugins", "a", "x.html") {
		t.Errorf("x.html is %q, want the first claim's", rel)
	}
}

// Hidden and underscored directories are not plugins, nor is a stray file.
func TestOnlyPluginDirectoriesAreLookedAt(t *testing.T) {
	dir := web(t, map[string]string{
		".git/plugin.json":     `{}`,
		"_scratch/plugin.json": `{}`,
		"README":               "notes",
	})
	if r := Discover(dir, quiet(), noneReserved, nil); len(r.Status()) != 0 {
		t.Fatalf("status = %+v", r.Status())
	}
}

// No plugins directory at all is a valid server.
func TestNoPluginsDirectoryIsNoPlugins(t *testing.T) {
	r := Discover(t.TempDir(), quiet(), noneReserved, nil)
	if s := r.Status(); s == nil || len(s) != 0 {
		t.Errorf("Status() = %#v", s)
	}
	var none *Registry
	if _, ok := none.File("x"); ok {
		t.Error("a nil registry serves something")
	}
}

// The generator links in exactly the directories Discover expects code from.
func TestTheGeneratorImportsExactlyThePluginsWithCode(t *testing.T) {
	dir := web(t, map[string]string{
		"tg/plugin.json":    `{}`,
		"tg/tg.go":          "package tg",
		"con/plugin.json":   `{}`,
		"con/con.html":      "",
		"only/only_test.go": "package only", // tests alone are not code
		"_off/off.go":       "package off",
		"zz/plugin.json":    `{}`,
		"zz/zz.go":          "package zz",
	})
	src, err := GenerateImports(filepath.Join(dir, "plugins"), "example.com/web/plugins")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{`_ "example.com/web/plugins/tg"`, `_ "example.com/web/plugins/zz"`, "package main", "DO NOT EDIT"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in:\n%s", want, s)
		}
	}
	for _, not := range []string{"/con", "/only", "/_off"} {
		if strings.Contains(s, not) {
			t.Errorf("imports %s, which has no code:\n%s", not, s)
		}
	}
	if strings.Index(s, "/tg") > strings.Index(s, "/zz") {
		t.Errorf("imports out of order:\n%s", s)
	}
}
