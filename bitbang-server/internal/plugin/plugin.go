// Package plugin hosts the server's features that are not signaling.
//
// The design is plugin-model.md in bitbang-docs. This is its first stage,
// and deliberately only that: a plugin can put files into the browser
// runtime -- a meta-page, a panel, a module they import -- and nothing else
// yet. Each later mechanism (routes, config, events, the registered hook,
// one plugin calling another) arrives with the first plugin that needs it,
// because a mechanism with no consumer has nothing to test its shape against.
//
// Plugins are Go packages compiled into the server and listed in main.go.
// No manifest file: the compiler checks a Go value, and there is nothing to
// parse.
package plugin

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Plugin is one feature. Name is its namespace everywhere -- the directory its
// files live in, the plugin= field on its log lines -- so it has to be stable.
type Plugin interface {
	Name() string
	Init(Host) error
}

// Host is what a plugin can ask of the server. It grows a method per stage,
// and only when a plugin needs one.
type Host interface {
	Name() string
	Logger() *slog.Logger

	// MetaPage serves <name>.html as the meta-page *<name>: the service worker
	// fetches /__bitbang__/<name>.html when someone opens #<code>/*<name>.
	MetaPage(name string) error

	// Panel serves <name>-panel.js, the module a device page embeds with
	// data-bitbang-page="<name>".
	Panel(name string) error

	// File serves any other file the plugin's pages load by name -- a module
	// they import, a worklet.
	File(name string) error
}

// Status is one plugin's line on /status.
type Status struct {
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	Error string `json:"error,omitempty"`
}

// The service worker's meta-page URL pattern is [A-Za-z0-9_-]+, and a panel
// name ends up in an attribute selector; anything else is unreachable.
var validName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Registry is what the loaded plugins contributed.
//
// Files are served at /__bitbang__/<file>, the browser runtime's one flat
// namespace, rather than under /plug/<name>/. Everything that asks for them
// asks by that spelling and cannot be changed lightly: the service worker
// resolves *<name> to /__bitbang__/<name>.html, bitbang.js -- whose URL is
// compiled into firmware -- loads panels from there, and the panels import the
// modules they share by relative path. Meta-page and panel names are global
// anyway (#<code>/*console, data-bitbang-page="console"), so the registry
// refuses a second claim to one rather than prefixing it away. /plug/<name>/ is
// for a plugin's own routes, when there are any.
type Registry struct {
	dir string

	files     map[string]string // served name -> path relative to dir
	owner     map[string]string // served name -> plugin
	metaPages []string
	panels    []string
	status    []Status
}

// Load initializes each plugin in order and keeps what each registered.
//
// A plugin that fails -- an error from Init, a panic, a file missing from its
// directory, a name somebody else has -- is reported on /status and left out
// entirely: what it registered before failing is dropped with it, so nothing
// is served by a plugin that is down. The server comes up either way; one bad
// plugin does not take the others with it.
//
// reserved reports the names the core serves itself, which no plugin may take:
// the core's copy would win, and the plugin's would be unreachable with no
// error anywhere.
func Load(staticDir string, log *slog.Logger, reserved func(string) bool, plugins ...Plugin) *Registry {
	r := &Registry{
		dir:   staticDir,
		files: map[string]string{},
		owner: map[string]string{},
	}
	seen := map[string]bool{}
	for _, p := range plugins {
		name := p.Name()
		st := Status{Name: name}
		switch {
		case !validName.MatchString(name):
			st.Error = "invalid plugin name"
		case seen[name]:
			st.Error = "loaded twice"
		default:
			seen[name] = true
			h := &host{reg: r, name: name, log: log.With("plugin", name), reserved: reserved}
			if err := initSafely(p, h); err != nil {
				st.Error = err.Error()
			} else {
				r.commit(h)
				st.Up = true
			}
		}
		if st.Up {
			log.Info("plugin up", "plugin", name)
		} else {
			log.Error("plugin down", "plugin", name, "err", st.Error)
		}
		r.status = append(r.status, st)
	}
	return r
}

// initSafely turns a panic in Init into an error, attributed to the plugin.
func initSafely(p Plugin, h *host) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("panic in Init: %v", v)
		}
	}()
	return p.Init(h)
}

func (r *Registry) commit(h *host) {
	for served, rel := range h.files {
		r.files[served] = rel
		r.owner[served] = h.name
	}
	r.metaPages = append(r.metaPages, h.metaPages...)
	r.panels = append(r.panels, h.panels...)
}

// File returns where a served name is on disk, relative to the static
// directory.
func (r *Registry) File(name string) (string, bool) {
	if r == nil {
		return "", false
	}
	rel, ok := r.files[name]
	return rel, ok
}

// MetaPages returns the meta-page names the plugins registered, sorted.
func (r *Registry) MetaPages() []string {
	if r == nil {
		return nil
	}
	out := append([]string(nil), r.metaPages...)
	sort.Strings(out)
	return out
}

// Panels returns the panel names the plugins registered, sorted.
func (r *Registry) Panels() []string {
	if r == nil {
		return nil
	}
	out := append([]string(nil), r.panels...)
	sort.Strings(out)
	return out
}

// Files returns every registered file's path relative to the static
// directory, sorted -- the plugins' share of the build stamp's inputs. Sorted,
// because the stamp hashes them in order and map order would move it on every
// restart.
func (r *Registry) Files() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.files))
	for _, rel := range r.files {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// Status returns every plugin's line, in load order. Never nil, so /status
// says "plugins": [] rather than null when there are none.
func (r *Registry) Status() []Status {
	out := []Status{}
	if r == nil {
		return out
	}
	return append(out, r.status...)
}

// host stages one plugin's registrations, so a plugin that fails part way
// through Init leaves nothing behind.
type host struct {
	reg      *Registry
	name     string
	log      *slog.Logger
	reserved func(string) bool

	files     map[string]string
	metaPages []string
	panels    []string
}

func (h *host) Name() string         { return h.name }
func (h *host) Logger() *slog.Logger { return h.log }

func (h *host) MetaPage(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("meta-page %q: names are [A-Za-z0-9_-]+", name)
	}
	if err := h.File(name + ".html"); err != nil {
		return err
	}
	h.metaPages = append(h.metaPages, name)
	return nil
}

func (h *host) Panel(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("panel %q: names are [A-Za-z0-9_-]+", name)
	}
	if err := h.File(name + "-panel.js"); err != nil {
		return err
	}
	h.panels = append(h.panels, name)
	return nil
}

// File checks everything that would otherwise surface as a 404 in a browser:
// the name is flat, nobody else serves it, and the file is really there.
func (h *host) File(name string) error {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return fmt.Errorf("file %q: a flat name, no directories", name)
	}
	if h.reserved != nil && h.reserved(name) {
		return fmt.Errorf("file %q: the core serves that name", name)
	}
	if owner, taken := h.reg.owner[name]; taken {
		return fmt.Errorf("file %q: already served by plugin %q", name, owner)
	}
	if _, staged := h.files[name]; staged {
		return fmt.Errorf("file %q: registered twice", name)
	}
	rel := filepath.Join("plugins", h.name, name)
	if _, err := os.Stat(filepath.Join(h.reg.dir, rel)); err != nil {
		return fmt.Errorf("file %q: %w", name, err)
	}
	if h.files == nil {
		h.files = map[string]string{}
	}
	h.files[name] = rel
	return nil
}
