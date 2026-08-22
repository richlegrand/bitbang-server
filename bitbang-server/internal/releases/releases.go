// Package releases tracks the newest published version of each BitBang
// client project, so the signaling server can tell a device about an
// update in the reply to a registration it was already making.
//
// The point of doing it here rather than in the clients is disclosure.
// A client that checks GitHub for itself tells GitHub that its IP runs
// BitBang, on a schedule, forever -- and a self-hoster who stood up
// their own signaling server to avoid anyone's infrastructure would be
// phoning a third party anyway. Polling from the server turns that into
// one request per interval from one host, and the clients send nothing:
// not a version, not a product name, not an extra request. They receive
// the whole table and decide locally whether they care.
//
// Nothing here is on the registration path. Poll results land in a
// cached map; a registration reads whatever is there. GitHub being slow,
// broken, or unreachable makes the table stale or empty, never a slow
// registration.
package releases

import (
	"context"
	"log/slog"
	"net/http"
	"path"
	"sync"
	"time"
)

// Repo is one project to watch: a GitHub "owner/name", and the key
// clients look themselves up under. They differ (Octoprint-BitBang vs
// "octoprint"), and the key is what ends up on the wire, so it is worth
// keeping stable even if the repo is renamed.
type Repo struct {
	Repo string // "richlegrand/bitbang-cli"
	Key  string // "cli"
}

// Tracker polls GitHub and caches the latest tag per key.
type Tracker struct {
	repos    []Repo
	interval time.Duration
	client   *http.Client
	log      *slog.Logger

	mu     sync.RWMutex
	latest map[string]string

	// base is the GitHub origin, overridden by tests. Production never
	// sets it.
	base string
}

// New builds a Tracker. A nil return means "not configured" -- no repos,
// so no polling and no outbound requests at all. That is the default for
// anyone running their own server: they opt in or they phone nobody.
func New(repos []Repo, interval time.Duration, log *slog.Logger) *Tracker {
	if len(repos) == 0 {
		return nil
	}
	if interval <= 0 {
		interval = time.Hour
	}
	return &Tracker{
		repos:    repos,
		interval: interval,
		log:      log,
		latest:   make(map[string]string, len(repos)),
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Read the redirect rather than following it: the tag is in
			// the Location header, and stopping here avoids fetching the
			// release page we do not want.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Latest returns a copy of the current table. A nil Tracker returns nil,
// so callers do not need to check for one.
func (t *Tracker) Latest() map[string]string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.latest) == 0 {
		return nil
	}
	out := make(map[string]string, len(t.latest))
	for k, v := range t.latest {
		out[k] = v
	}
	return out
}

// Run polls once immediately, then every interval, until ctx is done.
// Safe to call on a nil Tracker.
func (t *Tracker) Run(ctx context.Context) {
	if t == nil {
		return
	}
	t.pollAll(ctx)
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.pollAll(ctx)
		}
	}
}

func (t *Tracker) pollAll(ctx context.Context) {
	for _, r := range t.repos {
		tag, err := t.latestTag(ctx, r.Repo)
		if err != nil {
			// Keep the previous value. A transient GitHub failure should
			// not retract an answer we already had -- the old version is
			// still true, just possibly not the newest.
			t.log.Debug("release poll failed", "repo", r.Repo, "err", err)
			continue
		}
		if tag == "" {
			// 404 or no redirect: the repo is private, renamed, or has no
			// published release. Also not a reason to drop a good value.
			continue
		}
		t.mu.Lock()
		changed := t.latest[r.Key] != tag
		t.latest[r.Key] = tag
		t.mu.Unlock()
		if changed {
			t.log.Info("latest release", "key", r.Key, "repo", r.Repo, "tag", tag)
		}
	}
}

// latestTag reads the tag that /releases/latest redirects to. This uses
// the plain web endpoint rather than api.github.com deliberately: the
// API costs 10KB of JSON against a 60/hour unauthenticated quota, while
// the redirect is a 0-byte HEAD with no quota and no response shape to
// break.
//
// An empty tag with a nil error means "no release to report" (404, or a
// repo with no releases), which the caller treats as leave-as-is rather
// than as a failure.
func (t *Tracker) latestTag(ctx context.Context, repo string) (string, error) {
	base := t.base
	if base == "" {
		base = "https://github.com"
	}
	url := base + "/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", nil
	}
	tag := path.Base(loc)
	// A repo with zero releases redirects to .../releases, whose base is
	// the word itself rather than a tag.
	if tag == "releases" || tag == "" || tag == "." || tag == "/" {
		return "", nil
	}
	return tag, nil
}

// NewForTest is New with the GitHub origin overridden, for tests in
// other packages that need a Tracker without reaching the network.
func NewForTest(repos []Repo, interval time.Duration, log *slog.Logger, base string) *Tracker {
	t := New(repos, interval, log)
	if t != nil {
		t.base = base
	}
	return t
}

// PollOnce runs a single poll cycle. Exported for tests that want a
// populated table without starting the ticker.
func (t *Tracker) PollOnce(ctx context.Context) {
	if t == nil {
		return
	}
	t.pollAll(ctx)
}
