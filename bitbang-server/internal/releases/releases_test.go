package releases

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeGitHub redirects /<owner>/<repo>/releases/latest the way GitHub
// does, driven by a table the test controls.
func fakeGitHub(t *testing.T, tags map[string]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		// "/owner/name/releases/latest"
		path := r.URL.Path
		for repo, tag := range tags {
			if path == "/"+repo+"/releases/latest" {
				switch tag {
				case "": // repo exists, no releases
					http.Redirect(w, r, "/"+repo+"/releases", http.StatusFound)
				default:
					http.Redirect(w, r, "/"+repo+"/releases/tag/"+tag, http.StatusFound)
				}
				return
			}
		}
		http.NotFound(w, r)
	}))
}

func track(t *testing.T, srv *httptest.Server, repos ...Repo) *Tracker {
	t.Helper()
	tr := New(repos, time.Hour, quiet())
	if tr == nil {
		t.Fatal("New returned nil for a non-empty repo list")
	}
	tr.base = srv.URL
	return tr
}

func TestPollReadsTheRedirectTag(t *testing.T) {
	srv := fakeGitHub(t, map[string]string{
		"o/cli":  "0.4.7",
		"o/plug": "1.2.0",
	}, nil)
	defer srv.Close()

	tr := track(t, srv, Repo{"o/cli", "cli"}, Repo{"o/plug", "octoprint"})
	tr.pollAll(context.Background())

	got := tr.Latest()
	if got["cli"] != "0.4.7" || got["octoprint"] != "1.2.0" {
		t.Fatalf("got %v", got)
	}
}

// Every client receives the same table, so a copy has to be handed out --
// otherwise a caller could mutate the shared map.
func TestLatestReturnsACopy(t *testing.T) {
	srv := fakeGitHub(t, map[string]string{"o/cli": "0.4.7"}, nil)
	defer srv.Close()
	tr := track(t, srv, Repo{"o/cli", "cli"})
	tr.pollAll(context.Background())

	tr.Latest()["cli"] = "999.0.0"
	if tr.Latest()["cli"] != "0.4.7" {
		t.Fatal("Latest handed out the live map")
	}
}

// A server that tracks nothing must make no requests at all -- that is
// what a self-hoster gets by default.
func TestUnconfiguredIsInert(t *testing.T) {
	var hits int32
	srv := fakeGitHub(t, map[string]string{"o/cli": "0.4.7"}, &hits)
	defer srv.Close()

	tr := New(nil, time.Hour, quiet())
	if tr != nil {
		t.Fatal("New should return nil with no repos")
	}
	// All three are nil-safe, which is what lets call sites skip the check.
	tr.Run(context.Background())
	if got := tr.Latest(); got != nil {
		t.Fatalf("nil tracker returned %v", got)
	}
	if hits != 0 {
		t.Fatalf("made %d requests while unconfigured", hits)
	}
}

// A repo that 404s, or has no release, must not retract a value we
// already had. The old version is still true, just maybe not newest.
func TestFailureKeepsThePreviousValue(t *testing.T) {
	tags := map[string]string{"o/cli": "0.4.7"}
	srv := fakeGitHub(t, tags, nil)
	defer srv.Close()
	tr := track(t, srv, Repo{"o/cli", "cli"})

	tr.pollAll(context.Background())
	if tr.Latest()["cli"] != "0.4.7" {
		t.Fatal("first poll failed")
	}

	// Repo vanishes (renamed, made private).
	delete(tags, "o/cli")
	tr.pollAll(context.Background())
	if got := tr.Latest()["cli"]; got != "0.4.7" {
		t.Fatalf("a 404 retracted the value: got %q", got)
	}
}

// A repo with no published release redirects to /releases, whose last
// path segment is the word itself rather than a tag.
func TestRepoWithNoReleasesReportsNothing(t *testing.T) {
	srv := fakeGitHub(t, map[string]string{"o/fresh": ""}, nil)
	defer srv.Close()
	tr := track(t, srv, Repo{"o/fresh", "fresh"})
	tr.pollAll(context.Background())
	if got := tr.Latest(); got != nil {
		t.Fatalf(`got %v, want nothing -- "releases" is not a version`, got)
	}
}

func TestRunPollsImmediatelyThenStops(t *testing.T) {
	var hits int32
	srv := fakeGitHub(t, map[string]string{"o/cli": "0.4.7"}, &hits)
	defer srv.Close()
	tr := track(t, srv, Repo{"o/cli", "cli"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx); close(done) }()

	deadline := time.After(3 * time.Second)
	for tr.Latest()["cli"] == "" {
		select {
		case <-deadline:
			t.Fatal("Run did not poll on start")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
}
