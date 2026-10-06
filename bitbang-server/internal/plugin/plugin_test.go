package plugin

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fake is a plugin whose Init is whatever the test says.
type fake struct {
	name string
	init func(Host) error
}

func (f fake) Name() string      { return f.name }
func (f fake) Init(h Host) error { return f.init(h) }
func quiet() *slog.Logger        { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func noneReserved(string) bool   { return false }
func reservedIs(name string) func(string) bool {
	return func(s string) bool { return s == name }
}

// web writes files under dir/plugins/<plugin>/ and returns dir.
func web(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		path := filepath.Join(dir, "plugins", f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func up(t *testing.T, r *Registry, name string) bool {
	t.Helper()
	for _, st := range r.Status() {
		if st.Name == name {
			return st.Up
		}
	}
	t.Fatalf("no status line for %s", name)
	return false
}

// A meta-page and a panel land at their flat names, from the plugin's own
// directory, and count toward the stamp.
func TestARegisteredPageIsServedFromItsDirectory(t *testing.T) {
	dir := web(t, "con/con.html", "con/con-panel.js")
	r := Load(dir, quiet(), noneReserved, fake{"con", func(h Host) error {
		if err := h.MetaPage("con"); err != nil {
			return err
		}
		return h.Panel("con")
	}})

	if !up(t, r, "con") {
		t.Fatalf("down: %+v", r.Status())
	}
	if rel, ok := r.File("con.html"); !ok || rel != filepath.Join("plugins", "con", "con.html") {
		t.Errorf("con.html -> %q, %v", rel, ok)
	}
	if !reflect.DeepEqual(r.MetaPages(), []string{"con"}) {
		t.Errorf("MetaPages = %v", r.MetaPages())
	}
	if !reflect.DeepEqual(r.Panels(), []string{"con"}) {
		t.Errorf("Panels = %v", r.Panels())
	}
	want := []string{filepath.Join("plugins", "con", "con-panel.js"), filepath.Join("plugins", "con", "con.html")}
	if !reflect.DeepEqual(r.Files(), want) {
		t.Errorf("Files = %v, want %v", r.Files(), want)
	}
}

// The failures it exists to turn from a silent 404 into a /status line. In
// each, the plugin is down and serves nothing -- including what it registered
// before the failure.
func TestAFailingPluginServesNothing(t *testing.T) {
	cases := []struct {
		name     string
		files    []string
		reserved func(string) bool
		init     func(Host) error
	}{
		{"missing file", nil, noneReserved, func(h Host) error {
			return h.MetaPage("p")
		}},
		{"a core name", []string{"p/sw.js"}, reservedIs("sw.js"), func(h Host) error {
			return h.File("sw.js")
		}},
		{"a path, not a name", []string{"p/a/b.js"}, noneReserved, func(h Host) error {
			return h.File("a/b.js")
		}},
		{"an invalid meta-page name", []string{"p/a b.html"}, noneReserved, func(h Host) error {
			return h.MetaPage("a b")
		}},
		{"Init's own error, after registering", []string{"p/p.html"}, noneReserved, func(h Host) error {
			if err := h.MetaPage("p"); err != nil {
				return err
			}
			return errors.New("not today")
		}},
		{"a panic, after registering", []string{"p/p.html"}, noneReserved, func(h Host) error {
			_ = h.MetaPage("p")
			panic("boom")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Load(web(t, c.files...), quiet(), c.reserved, fake{"p", c.init})
			st := r.Status()[0]
			if st.Up || st.Error == "" {
				t.Fatalf("status = %+v, want down with a reason", st)
			}
			if len(r.Files()) != 0 || len(r.MetaPages()) != 0 {
				t.Errorf("a down plugin still serves %v / %v", r.Files(), r.MetaPages())
			}
		})
	}
}

// Two plugins claiming one name: the first keeps it, the second is down, and
// the rest still load.
func TestASecondClaimToANameIsRefused(t *testing.T) {
	dir := web(t, "a/x.html", "b/x.html", "c/c.html")
	page := func(n string) func(Host) error { return func(h Host) error { return h.MetaPage(n) } }
	r := Load(dir, quiet(), noneReserved,
		fake{"a", page("x")}, fake{"b", page("x")}, fake{"c", page("c")})

	if !up(t, r, "a") || up(t, r, "b") || !up(t, r, "c") {
		t.Fatalf("status = %+v", r.Status())
	}
	if rel, _ := r.File("x.html"); rel != filepath.Join("plugins", "a", "x.html") {
		t.Errorf("x.html is %q, want the first claim's", rel)
	}
}

func TestAPluginLoadedTwiceIsRefused(t *testing.T) {
	dir := web(t, "a/a.html")
	p := fake{"a", func(h Host) error { return h.MetaPage("a") }}
	r := Load(dir, quiet(), noneReserved, p, p)
	st := r.Status()
	if len(st) != 2 || !st[0].Up || st[1].Up {
		t.Fatalf("status = %+v", st)
	}
}

// No plugins is a valid server, and /status says so with an empty list.
func TestNoRegistryIsEmptyNotNil(t *testing.T) {
	var r *Registry
	if s := r.Status(); s == nil || len(s) != 0 {
		t.Errorf("Status() = %#v", s)
	}
	if _, ok := r.File("x"); ok {
		t.Error("a nil registry serves something")
	}
}
