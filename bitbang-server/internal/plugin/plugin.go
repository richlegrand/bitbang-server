// Package plugin hosts the server's features that are not signaling.
//
// The design is plugin-model.md in bitbang-docs. A plugin is a directory,
// web/plugins/<name>/, and its being there is what turns it on:
//
//   - plugin.json says what the browser runtime loads from it by name -- its
//     meta-pages, panels and other files. A plugin with no server behavior is
//     nothing more than that and its files; adding one is adding a directory.
//   - Go files in the same directory make a plugin with server behavior. The
//     package registers itself from init() (Register), and the build links
//     every such package in through a generated file of imports
//     (cmd/signaling/plugins_gen.go, from `go generate ./cmd/signaling`). So
//     no list of plugins is kept by hand anywhere.
//
// One binary serves every deployment: a plugin compiled in stays off unless
// its directory is in the deployed web/plugins/.
//
// The host is still small -- the files the runtime loads, a logger, and Init
// for the plugins with code. Each later mechanism (routes, config, events, the
// registered hook, one plugin calling another) arrives with the first plugin
// that needs it, because a mechanism with no consumer has nothing to test its
// shape against.
package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Plugin is a plugin's server behavior: the code in its directory. Name is the
// directory's name.
type Plugin interface {
	Name() string
	Init(Host) error
}

var (
	registeredMu sync.Mutex
	registered   []Plugin
)

// Register is called from a plugin package's init(), which runs because the
// generated plugins_gen.go imports the package. Being linked in is being
// registered; there is no list to add the plugin to.
func Register(p Plugin) {
	registeredMu.Lock()
	defer registeredMu.Unlock()
	registered = append(registered, p)
}

// Registered returns every plugin whose code is linked into this binary.
func Registered() []Plugin {
	registeredMu.Lock()
	defer registeredMu.Unlock()
	return append([]Plugin(nil), registered...)
}

// Host is what a plugin's code can ask of the server. It grows a method per
// stage, and only when a plugin needs one. The manifest goes through the same
// three file methods, so a page registered in plugin.json and one registered
// from Init are checked alike.
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

// Manifest is plugin.json. Unknown fields are an error, so a misspelled key
// says so rather than quietly registering nothing.
type Manifest struct {
	MetaPages []string `json:"meta_pages"`
	Panels    []string `json:"panels"`
	Files     []string `json:"files"`
}

// ManifestName is the file that makes a directory under plugins/ a plugin.
const ManifestName = "plugin.json"

// Status is one plugin's line on /status.
type Status struct {
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	Error string `json:"error,omitempty"`
}

// The service worker's meta-page URL pattern is [A-Za-z0-9_-]+, and a panel
// name ends up in an attribute selector; anything else is unreachable. The
// same pattern makes a plugin's directory name a valid Go package path element.
var validName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Registry is what the deployed plugins contributed.
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

// Discover turns on every plugin whose directory is in staticDir/plugins/:
// it registers what the directory's plugin.json lists, then runs Init for a
// plugin with code. code is the plugins linked into the binary -- Registered()
// in the server, fakes in a test.
//
// A plugin that fails -- no plugin.json, a manifest that doesn't parse, a file
// missing from its directory, a name somebody else has, Go files whose code
// isn't linked in, an error or a panic from Init -- is reported on /status and
// left out entirely: what it registered before failing is dropped with it, so
// nothing is served by a plugin that is down. The server comes up either way;
// one bad plugin does not take the others with it.
//
// reserved reports the names the core serves itself, which no plugin may take:
// the core's copy would win, and the plugin's would be unreachable with no
// error anywhere.
func Discover(staticDir string, log *slog.Logger, reserved func(string) bool, code []Plugin) *Registry {
	r := &Registry{
		dir:   staticDir,
		files: map[string]string{},
		owner: map[string]string{},
	}

	byName := map[string]Plugin{}
	twice := map[string]bool{}
	for _, p := range code {
		if _, dup := byName[p.Name()]; dup {
			twice[p.Name()] = true
		}
		byName[p.Name()] = p
	}

	root := filepath.Join(staticDir, "plugins")
	entries, err := os.ReadDir(root)
	if err != nil && !os.IsNotExist(err) {
		log.Error("plugins: cannot read directory", "dir", root, "err", err)
	}
	deployed := map[string]bool{}
	for _, e := range entries {
		// .git, _scratch and the like are not plugins, and neither is a stray
		// file at the top level.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		name := e.Name()
		deployed[name] = true
		st := Status{Name: name}
		p, compiled := byName[name]
		switch {
		case !validName.MatchString(name):
			st.Error = "invalid plugin name"
		case twice[name]:
			st.Error = "two packages register this name"
		case HasCode(filepath.Join(root, name)) && !compiled:
			st.Error = "has Go code that isn't compiled in: run go generate ./cmd/signaling and rebuild"
		default:
			h := &host{reg: r, name: name, log: log.With("plugin", name), reserved: reserved}
			if err := h.load(filepath.Join(root, name), p); err != nil {
				st.Error = err.Error()
			} else {
				r.commit(h)
				st.Up = true
			}
		}
		if st.Up {
			log.Info("plugin up", "plugin", name, "code", compiled)
		} else {
			log.Error("plugin down", "plugin", name, "err", st.Error)
		}
		r.status = append(r.status, st)
	}

	// Compiled in and not deployed is a deployment's choice, not a fault: one
	// binary, and each deployment's web/plugins/ says what is on.
	for name := range byName {
		if !deployed[name] {
			log.Info("plugin compiled in but not deployed; off", "plugin", name)
		}
	}
	return r
}

// load registers what the manifest lists, then runs the plugin's own Init if
// it has code. Both through the same staged host, so a failure in either
// leaves nothing behind.
func (h *host) load(dir string, p Plugin) error {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return fmt.Errorf("no %s: %w", ManifestName, err)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("%s: %w", ManifestName, err)
	}
	for _, n := range m.MetaPages {
		if err := h.MetaPage(n); err != nil {
			return err
		}
	}
	for _, n := range m.Panels {
		if err := h.Panel(n); err != nil {
			return err
		}
	}
	for _, n := range m.Files {
		if err := h.File(n); err != nil {
			return err
		}
	}
	if p != nil {
		return initSafely(p, h)
	}
	return nil
}

// HasCode reports whether a plugin directory holds Go code: any .go file that
// isn't a test. The generator links in exactly these, and Discover expects to
// find exactly these registered -- one definition, so the two can't disagree.
func HasCode(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			return true
		}
	}
	return false
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

// Status returns every deployed plugin's line, in directory order. Never nil,
// so /status says "plugins": [] rather than null when there are none.
func (r *Registry) Status() []Status {
	out := []Status{}
	if r == nil {
		return out
	}
	return append(out, r.status...)
}

// host stages one plugin's registrations, so a plugin that fails part way
// through leaves nothing behind.
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
	if name == ManifestName || strings.HasSuffix(name, ".go") {
		return fmt.Errorf("file %q: the plugin's own definition, not something to serve", name)
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
