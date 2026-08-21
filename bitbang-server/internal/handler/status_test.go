package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bitbang-server-go/internal/metrics"
	"bitbang-server-go/internal/registry"
)

func statusDeps(token string) *Deps {
	return &Deps{
		Devices:     registry.NewMemoryRegistry(),
		Clients:     registry.NewClientRegistry(),
		Metrics:     metrics.New(),
		StatusToken: token,
	}
}

// behindNginx mirrors production: TRUST_PROXY_HEADERS=true, and nginx on
// the same host, so every proxied request arrives from loopback with the
// real client in X-Real-IP.
func behindNginx(token string) *Deps {
	d := statusDeps(token)
	d.TrustProxyHeaders = true
	return d
}

// get issues GET /status from remoteAddr with an optional Authorization
// header, and returns the recorder.
func get(d *Deps, remoteAddr, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = remoteAddr
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	d.Status(w, r)
	return w
}

// An operator who sets nothing sees no change.
func TestStatusPublicWithoutToken(t *testing.T) {
	w := get(statusDeps(""), "203.0.113.7:5555", "")
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, ok := body["devices"]; !ok {
		t.Error("payload is missing devices")
	}
}

func TestStatusTokenGates(t *testing.T) {
	d := statusDeps("s3cret")
	cases := []struct {
		name, remote, auth string
		want               int
	}{
		{"no header", "203.0.113.7:5555", "", http.StatusNotFound},
		{"wrong token", "203.0.113.7:5555", "Bearer nope", http.StatusNotFound},
		{"bare token, no scheme", "203.0.113.7:5555", "s3cret", http.StatusNotFound},
		{"right token", "203.0.113.7:5555", "Bearer s3cret", http.StatusOK},
		{"loopback v4 is exempt", "127.0.0.1:5555", "", http.StatusOK},
		{"loopback v6 is exempt", "[::1]:5555", "", http.StatusOK},
		{"a LAN address is not loopback", "192.168.1.9:5555", "", http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := get(d, c.remote, c.auth).Code; got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// X-Forwarded-For is attacker-controlled. Claiming to be localhost must
// not work, or the token guards nothing behind a reverse proxy.
func TestStatusIgnoresForwardedFor(t *testing.T) {
	d := statusDeps("s3cret")
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		t.Run(h, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/status", nil)
			r.RemoteAddr = "203.0.113.7:5555"
			r.Header.Set(h, "127.0.0.1")
			w := httptest.NewRecorder()
			d.Status(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s spoofed loopback: got %d, want 404", h, w.Code)
			}
		})
	}
}

// The whole gate turns on this. Production runs nginx on the same host,
// so a public request's RemoteAddr *is* loopback -- reading it directly
// would exempt the entire internet from the token.
func TestStatusBehindSameHostProxy(t *testing.T) {
	d := behindNginx("s3cret")

	t.Run("public request proxied from loopback still needs the token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.RemoteAddr = "127.0.0.1:5555"          // nginx, same host
		r.Header.Set("X-Real-IP", "203.0.113.7") // the actual caller
		w := httptest.NewRecorder()
		d.Status(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("got %d, want 404 -- the internet just read /status", w.Code)
		}
	})

	t.Run("and is served with it", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("Authorization", "Bearer s3cret")
		w := httptest.NewRecorder()
		d.Status(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", w.Code)
		}
	})

	// The deploy script curls localhost directly, bypassing nginx, so no
	// X-Real-IP is set and it stays exempt.
	t.Run("deploy script bypassing nginx is exempt", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		w := httptest.NewRecorder()
		d.Status(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200 -- the deploy script lost its status read", w.Code)
		}
	})
}
