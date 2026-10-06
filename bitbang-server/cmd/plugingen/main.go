// Command plugingen writes the file of imports that links every plugin with Go
// code into the signaling server. Run through `go generate ./cmd/signaling`;
// see the directive in cmd/signaling/main.go.
//
//	plugingen -dir ../../web/plugins -import bitbang-server-go/web/plugins -out plugins_gen.go
package main

import (
	"flag"
	"fmt"
	"os"

	"bitbang-server-go/internal/plugin"
)

func main() {
	dir := flag.String("dir", "", "the plugins directory to scan")
	prefix := flag.String("import", "", "the import path of that directory")
	out := flag.String("out", "", "the file to write")
	flag.Parse()
	if *dir == "" || *prefix == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "plugingen: -dir, -import and -out are all required")
		os.Exit(2)
	}

	src, err := plugin.GenerateImports(*dir, *prefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plugingen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "plugingen:", err)
		os.Exit(1)
	}
}
