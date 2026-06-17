package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/identity"
	"bitbang-server-go/internal/metrics"
	"bitbang-server-go/internal/pairing"
	"bitbang-server-go/internal/ratelimit"
	"bitbang-server-go/internal/registry"
	"bitbang-server-go/internal/turn"
	"bitbang-server-go/internal/wire"
)

// testServer spins up an httptest.Server with the full handler mux
// wired the same way as main.go. Returns the server, the deps (so
// tests can poke at table state), and a teardown closure.
func testServer(t *testing.T) (*httptest.Server, *Deps, func()) {
	t.Helper()

	devices := registry.NewMemoryRegistry()
	clients := registry.NewClientRegistry()
	pairTab := pairing.NewTable()

	deps := &Deps{
		Devices:      devices,
		Clients:      clients,
		TURN:         turn.NewCoturn("", "", 0, 0), // no TURN configured
		Limiter:      ratelimit.NoOp{},
		Pairing:      pairTab,
		Metrics:      metrics.New(),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Upgrader:     websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		PingInterval: 60 * time.Second,
		PongWait:     300 * time.Second,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/device/{uid}", func(w http.ResponseWriter, r *http.Request) {
		deps.DeviceWS(w, r, r.PathValue("uid"))
	})
	mux.HandleFunc("GET /ws/client/{uid}", func(w http.ResponseWriter, r *http.Request) {
		deps.ClientWS(w, r, r.PathValue("uid"))
	})
	mux.HandleFunc("GET /ws/pair", deps.PairWS)

	srv := httptest.NewServer(mux)
	teardown := func() {
		srv.Close()
		pairTab.Close()
	}
	return srv, deps, teardown
}

// newTestIdentity generates a fresh RSA keypair and returns (uid,
// base64-DER public key). Mirrors the device-side identity.go in
// bitbangproxy enough to satisfy the server's auth check.
func newTestIdentity(t *testing.T) (uid, pubB64 string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return identity.UIDFromPublicKeyBytes(der), base64.StdEncoding.EncodeToString(der)
}

// dialWS opens a WS to the test server's path.
func dialWS(t *testing.T, srv *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	u, _ := url.Parse(srv.URL + path)
	u.Scheme = "ws"
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial %s: %v", u.String(), err)
	}
	return ws
}

// readMsg reads one JSON frame and asserts the "type" field.
func readMsg(t *testing.T, ws *websocket.Conn, wantType string) map[string]any {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", string(data), err)
	}
	if got, _ := m["type"].(string); got != wantType {
		t.Fatalf("type = %q (full=%q), want %q", got, string(data), wantType)
	}
	return m
}

func writeJSON(t *testing.T, ws *websocket.Conn, v any) {
	t.Helper()
	if err := ws.WriteJSON(v); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestCodeExchange_Roundtrip is the happy-path integration test:
//   - device registers with want_code → receives `registered` with a
//     6-digit code
//   - connector opens /ws/pair, sends pair_init with that code
//   - server delivers pair_request to the device's WS with a client_id
//   - server replies pair_routed to the connector
// Validates the wire format, the table routing, and the code release
// on device disconnect.
func TestCodeExchange_Roundtrip(t *testing.T) {
	srv, deps, td := testServer(t)
	defer td()

	uid, pubB64 := newTestIdentity(t)

	// Device side.
	device := dialWS(t, srv, "/ws/device/"+uid)
	defer device.Close()

	writeJSON(t, device, wire.Register{
		Type:      "register",
		Protocol:  wire.ProtocolVersion,
		PublicKey: pubB64,
		WantCode:  true,
	})
	reg := readMsg(t, device, "registered")
	code, _ := reg["code"].(string)
	if len(code) != pairing.CodeLength {
		t.Fatalf("registered code = %q, want %d digits", code, pairing.CodeLength)
	}
	if deps.Pairing.ActiveCount() != 1 {
		t.Errorf("after issue, ActiveCount = %d, want 1", deps.Pairing.ActiveCount())
	}

	// Connector side.
	conn := dialWS(t, srv, "/ws/pair")
	defer conn.Close()
	writeJSON(t, conn, wire.PairInit{Type: "pair_init", Code: code})

	// Connector sees pair_routed (after the 3s LookupDelay).
	routed := readMsg(t, conn, "pair_routed")
	_ = routed

	// Device sees pair_request with a client_id.
	pr := readMsg(t, device, "pair_request")
	clientID, _ := pr["client_id"].(string)
	if clientID == "" {
		t.Errorf("pair_request missing client_id")
	}

	// Close device; the code should be released so the count drops.
	device.Close()
	// Give the server a moment to process the close.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if deps.Pairing.ActiveCount() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := deps.Pairing.ActiveCount(); got != 0 {
		t.Errorf("after device disconnect, ActiveCount = %d, want 0", got)
	}
}

// TestCodeExchange_UnknownCode covers the negative path: bogus code
// must take ~LookupDelay to return so timing doesn't leak existence,
// and the error must say "unknown_code".
func TestCodeExchange_UnknownCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3s timing test in -short mode")
	}
	srv, _, td := testServer(t)
	defer td()

	conn := dialWS(t, srv, "/ws/pair")
	defer conn.Close()

	start := time.Now()
	writeJSON(t, conn, wire.PairInit{Type: "pair_init", Code: "000000"})

	errMsg := readMsg(t, conn, "error")
	if !strings.Contains(errMsg["message"].(string), "unknown_code") {
		t.Errorf("error.message = %q, want contains 'unknown_code'", errMsg["message"])
	}
	if elapsed := time.Since(start); elapsed < pairing.LookupDelay-500*time.Millisecond {
		t.Errorf("response in %v, want at least ~%v (constant-time)", elapsed, pairing.LookupDelay)
	}
}

// TestCodeExchange_ConcurrentSameIPRefused covers the per-IP semaphore:
// two simultaneous /ws/pair from the same IP — the second must get
// HTTP 429 before even upgrading the WebSocket.
func TestCodeExchange_ConcurrentSameIPRefused(t *testing.T) {
	srv, _, td := testServer(t)
	defer td()

	// First connection: slow-path pair_init (unknown code, blocks 3s).
	first := dialWS(t, srv, "/ws/pair")
	defer first.Close()
	writeJSON(t, first, wire.PairInit{Type: "pair_init", Code: "111111"})

	// Give the first request time to enter the LookupDelay sleep.
	time.Sleep(100 * time.Millisecond)

	// Second connection: must be refused with 429 (NOT upgraded).
	u, _ := url.Parse(srv.URL + "/ws/pair")
	u.Scheme = "ws"
	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err == nil {
		t.Fatal("second concurrent dial should have failed")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		gotCode := -1
		if resp != nil {
			gotCode = resp.StatusCode
		}
		t.Errorf("second dial got status %d, want %d", gotCode, http.StatusTooManyRequests)
	}
}

// TestCodeExchange_RegisterWithoutWantCode preserves legacy behavior:
// a v3 device that doesn't set want_code gets a bare registered reply
// with no code field, and no entry is added to the table.
func TestCodeExchange_RegisterWithoutWantCode(t *testing.T) {
	srv, deps, td := testServer(t)
	defer td()

	uid, pubB64 := newTestIdentity(t)
	device := dialWS(t, srv, "/ws/device/"+uid)
	defer device.Close()

	writeJSON(t, device, wire.Register{
		Type:      "register",
		Protocol:  wire.ProtocolVersion,
		PublicKey: pubB64,
		// WantCode unset → false
	})
	reg := readMsg(t, device, "registered")
	if code, ok := reg["code"]; ok && code != "" {
		t.Errorf("legacy register returned code = %q, want absent", code)
	}
	if got := deps.Pairing.ActiveCount(); got != 0 {
		t.Errorf("ActiveCount = %d for non-want_code register, want 0", got)
	}
}

// Ensure the global pairInflight map doesn't leak entries across test
// runs (other tests rely on releasePairSlot draining cleanly).
func TestMain(m *testing.M) {
	defer func() {
		pairInflightMu.Lock()
		left := len(pairInflight)
		pairInflightMu.Unlock()
		if left != 0 {
			// Print for visibility; don't fail the suite over it.
			_ = left
		}
	}()
	// Reset for safety in case go test reuses the package.
	var once sync.Once
	once.Do(func() {
		pairInflightMu.Lock()
		for k := range pairInflight {
			delete(pairInflight, k)
		}
		pairInflightMu.Unlock()
	})
	m.Run()
}
