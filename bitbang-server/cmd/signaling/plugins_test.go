package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"bitbang-server-go/internal/handler"
	"bitbang-server-go/internal/plugin"
)

const webDir = "../../web"

// plugins_gen.go is generated, and a build uses whatever is committed. A plugin
// with code added without regenerating would be missing from the binary -- the
// server reports that on /status at startup, and this reports it before a
// deploy instead.
func TestGeneratedPluginImportsAreCurrent(t *testing.T) {
	want, err := plugin.GenerateImports(filepath.Join(webDir, "plugins"),
		"bitbang-server-go/web/plugins")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("plugins_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("plugins_gen.go is stale: run go generate ./cmd/signaling\n"+
			"--- committed\n%s\n--- generated\n%s", got, want)
	}
}

// Every plugin in the real web/ comes up, with the code this binary links in:
// each file a manifest lists is where it says, none collides with the core or
// another plugin, and every plugin with Go code has it compiled in. The host
// checks all of that at startup and takes a failing plugin down -- which in
// production is a page that 404s with only a /status line to say why. Here it
// is a test failure instead. In this package rather than the handler's because
// only here is plugins_gen.go linked in.
func TestEveryPluginComesUpAgainstTheRealWeb(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := plugin.Discover(webDir, log, handler.IsCoreAsset, plugin.Registered())
	if len(reg.Status()) == 0 {
		t.Fatal("no plugins found under web/plugins")
	}
	for _, st := range reg.Status() {
		if !st.Up {
			t.Errorf("plugin %s is down: %s", st.Name, st.Error)
		}
	}
}
