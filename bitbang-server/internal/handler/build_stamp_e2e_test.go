package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// connectToDevice brings a device up and attaches a client to it, over real
// sockets against a server whose Deps carry a stamp cache over dir. Returns a
// reader for the client socket and a cleanup.
func connectToDevice(t *testing.T, dir string) (read func(string) map[string]any, done func()) {
	t.Helper()
	srv, deps, teardown := testServer(t)
	deps.Stamps = NewStampCache(dir)

	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	if err := dev.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub,
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev, "registered")

	c := dialWS(t, srv, "/ws/client/"+uid)
	return func(want string) map[string]any { return readMsg(t, c, want) },
		func() { c.Close(); dev.Close(); teardown() }
}

// A client is told the build as soon as it connects.
//
// The common deploy restarts the server, so every client socket drops and the
// browser redials -- and this is what the redial is for. A page loaded before
// the deploy learns it is out of date from the first message on its new
// socket, instead of from a poll up to thirty minutes later.
func TestAClientIsToldTheBuildOnConnect(t *testing.T) {
	dir := stampDir(t)
	read, done := connectToDevice(t, dir)
	defer done()

	msg := read("build_stamp")
	if msg["build"] != NewStampCache(dir).Current() {
		t.Errorf("build = %v, want the stamp the files carry", msg["build"])
	}
}

// And told again when web/ changes under a running server.
//
// The other deploy: files replaced in place with no restart, so no socket
// drops and nothing redials. The stamp still moves -- StampCache follows the
// disk -- and each open socket passes that on within one interval.
func TestAClientIsToldWhenTheBuildChanges(t *testing.T) {
	recheckEveryTime(t)
	was := buildAnnounceEvery
	buildAnnounceEvery = 20 * time.Millisecond
	t.Cleanup(func() { buildAnnounceEvery = was })

	dir := stampDir(t)
	read, done := connectToDevice(t, dir)
	defer done()

	first := read("build_stamp")["build"]

	if err := os.WriteFile(filepath.Join(dir, "bootstrap.js"),
		[]byte("const BUILD = '"+buildPlaceholder+"';\n// revised\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	second := read("build_stamp")["build"]
	if second == first {
		t.Fatalf("told %v again after bootstrap.js changed", first)
	}
}
