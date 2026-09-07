package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bitbang-server-go/internal/releases"
)

// A device registers and is told the latest release of every BitBang
// client project, over a real websocket against the real handler. The
// unit tests either side of this seam can both pass while the field
// never reaches the wire.
func TestRegisteredCarriesVersions(t *testing.T) {
	srv, deps, teardown := testServer(t)
	defer teardown()

	trackCLIRelease(t, deps, "9.9.9")

	uid, pub := newTestIdentity(t)
	ws := dialWS(t, srv, "/ws/device/"+uid)
	defer ws.Close()

	if err := ws.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub,
	}); err != nil {
		t.Fatal(err)
	}

	reg := readMsg(t, ws, "registered")
	versions, ok := reg["versions"].(map[string]any)
	if !ok {
		t.Fatalf("no versions in the registered reply: %v", reg)
	}
	if versions["cli"] != "9.9.9" {
		t.Errorf("versions = %v, want cli 9.9.9", versions)
	}
}

// A server tracking nothing omits the field entirely, rather than
// sending an empty object -- so an older client sees exactly the reply
// it saw before this existed.
func TestRegisteredOmitsVersionsWhenUntracked(t *testing.T) {
	srv, deps, teardown := testServer(t)
	defer teardown()
	deps.Releases = nil

	uid, pub := newTestIdentity(t)
	ws := dialWS(t, srv, "/ws/device/"+uid)
	defer ws.Close()

	if err := ws.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub,
	}); err != nil {
		t.Fatal(err)
	}

	reg := readMsg(t, ws, "registered")
	if _, present := reg["versions"]; present {
		t.Errorf("versions present on an untracked server: %v", reg)
	}
}

// trackCLIRelease points deps at a tracker that has already seen one
// published cli release, standing in for GitHub so no test needs the
// network.
func trackCLIRelease(t *testing.T, deps *Deps, version string) {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/o/cli/releases/tag/"+version, http.StatusFound)
	}))
	t.Cleanup(gh.Close)

	tr := releases.NewForTest(
		[]releases.Repo{{Repo: "o/cli", Key: "cli"}},
		time.Hour,
		deps.Log,
		gh.URL,
	)
	tr.PollOnce(t.Context())
	deps.Releases = tr
}

// A connector is told the same table a device is, on both of the sockets
// it can arrive on. Nothing about the connection is involved in what it
// receives -- note there is no device registered here at all, and the
// hello still lands, ahead of the "Device not found" that follows.
func TestHelloCarriesVersionsToConnectors(t *testing.T) {
	uid, _ := newTestIdentity(t)
	for _, path := range []string{"/ws/client/" + uid, "/ws/pair"} {
		t.Run(path, func(t *testing.T) {
			srv, deps, teardown := testServer(t)
			defer teardown()
			trackCLIRelease(t, deps, "9.9.9")

			ws := dialWS(t, srv, path)
			defer ws.Close()

			hello := readMsg(t, ws, "hello")
			versions, ok := hello["versions"].(map[string]any)
			if !ok {
				t.Fatalf("no versions in the hello: %v", hello)
			}
			if versions["cli"] != "9.9.9" {
				t.Errorf("versions = %v, want cli 9.9.9", versions)
			}
		})
	}
}

// A server tracking nothing sends no hello at all, rather than an empty
// one: a connector against an older or untracking server sees exactly the
// socket it saw before this existed.
func TestNoHelloWhenUntracked(t *testing.T) {
	srv, deps, teardown := testServer(t)
	defer teardown()
	deps.Releases = nil

	// A registered device, so the connector socket stays open with
	// nothing to say -- otherwise the 3s not-found brake is what we
	// would be waiting on.
	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	defer dev.Close()
	writeJSON(t, dev, map[string]any{"type": "register", "protocol": 3, "public_key": pub})
	readMsg(t, dev, "registered")

	ws := dialWS(t, srv, "/ws/client/"+uid)
	defer ws.Close()

	_ = ws.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, data, err := ws.ReadMessage(); err == nil {
		t.Fatalf("server volunteered %q on an untracked server", string(data))
	}
}
