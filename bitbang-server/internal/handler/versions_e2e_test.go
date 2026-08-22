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

	// Stand in for GitHub so the test needs no network.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/o/cli/releases/tag/9.9.9", http.StatusFound)
	}))
	defer gh.Close()

	tr := releases.NewForTest(
		[]releases.Repo{{Repo: "o/cli", Key: "cli"}},
		time.Hour,
		deps.Log,
		gh.URL,
	)
	tr.PollOnce(t.Context())
	deps.Releases = tr

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
