// Package handler implements the HTTP and WebSocket endpoints of the
// signaling server.
//
// These endpoints are what every client speaks to: bitbang-cli, the browser
// runtime in web/, and bitbang-python. Wire-compatible behavior is the
// contract -- a change here is a change to all three at once.
package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/identity"
	"bitbang-server-go/internal/metrics"
	"bitbang-server-go/internal/pairing"
	"bitbang-server-go/internal/ratelimit"
	"bitbang-server-go/internal/registry"
	"bitbang-server-go/internal/releases"
	"bitbang-server-go/internal/turn"
	"bitbang-server-go/internal/wire"
)

// Deps bundles the dependencies the handlers need. main.go constructs this
// once and passes it in, keeping handler functions cheap to wire up.
type Deps struct {
	Devices *registry.MemoryRegistry
	Clients *registry.ClientRegistry
	TURN    turn.TURNProvider
	Limiter ratelimit.RateLimiter
	// Pairing is the code-exchange table. nil disables pairing entirely
	// (devices that ask for a code with want_code=true get a bare
	// registered reply without a code; pair_init endpoints return
	// 404 / unknown_code).
	Pairing *pairing.Table
	// Metrics collects connection-path counters reported by clients and
	// the request count seen by client_ws. Snapshot by /status. Always
	// non-nil; main.go constructs it at startup.
	Metrics *metrics.Metrics
	Log     *slog.Logger

	// Upgrader is the gorilla websocket upgrader, configured once.
	Upgrader websocket.Upgrader

	// PingInterval / PongWait control the keepalive cycle. Match Python:
	// websocket_ping_interval=60, keep_alive_timeout=300.
	PingInterval time.Duration
	PongWait     time.Duration

	// TrustProxyHeaders controls whether X-Real-IP / X-Forwarded-For are
	// honored when capturing the browser's IP for relayed "request"
	// messages. Enable only when the server runs behind a reverse proxy
	// that strips these headers from inbound requests; otherwise clients
	// can spoof the value.
	TrustProxyHeaders bool

	// StatusToken, when non-empty, restricts /status to requests bearing
	// it. Empty leaves /status public, which is what it was before this
	// existed -- so an operator who sets nothing sees no change.
	StatusToken string

	// Releases supplies the latest-version table stamped on the
	// registered reply. nil when nothing is tracked; its Latest() is
	// nil-safe, so no call site needs to check.
	Releases *releases.Tracker
}

// DeviceWS handles /ws/device/<uid>.
//
// Flow: upgrade → register (UID must equal hash(pubkey)) → preempt prior
// connection (if any) → enter relay loop. Proof of private-key possession is
// no longer demanded by the server; the browser-side bidirectional verify
// (encrypted fingerprint+nonce, hash(nonce) reply over DTLS) makes any
// imposter who claims a UID unable to complete a real session.
func (d *Deps) DeviceWS(w http.ResponseWriter, r *http.Request, uid string) {
	ip := d.clientIP(r)
	if !d.Limiter.Allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	ws, err := d.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote a response.
		return
	}
	defer ws.Close()

	d.setReadKeepalive(ws)
	d.startPingLoop(ws)

	connectAt := time.Now()
	conn := &registry.DeviceConn{UID: uid, WS: ws, ConnectAt: connectAt}

	regMsg, err := d.authenticateDevice(uid, conn)
	if err != nil {
		// authenticateDevice already sent an error frame.
		d.Log.Warn("device auth failed", "uid", uid, "remote", ip, "err", err)
		return
	}
	conn.PublicKey = regMsg.PublicKey

	// Preempt any existing connection for this UID. The newcomer satisfies the
	// same UID-binding check as the incumbent, so it takes precedence
	// (typically a device restart racing with its own stale ws). A real
	// imposter is harmless: they can claim a UID here but cannot complete the
	// browser-side bidirectional verify without the private key.
	if old := d.Devices.Add(uid, conn); old != nil {
		d.Log.Warn("device preempted", "uid", uid)
		_ = old.SendJSON(wire.Error{Type: "error", Message: "preempted"})
		old.Close(websocket.CloseNormalClosure, "preempted")

		// Boot any clients connected to the old device. Their existing
		// WebRTC peer connections were negotiated with the previous
		// device instance and won't carry over.
		for _, c := range d.Clients.ForTarget(uid) {
			_ = c.SendJSON(wire.Error{Type: "error", Message: "device_preempted"})
			c.Close(websocket.CloseNormalClosure, "device_preempted")
			d.Log.Info("booted client (device preempted)", "client_id", c.ClientID)
		}
	}

	// Apply device-supplied ICE override, if any.
	if len(regMsg.ICEServers) > 0 {
		conn.ICEServers = regMsg.ICEServers
		d.Log.Info("device registered (custom TURN)", "uid", uid)
	} else {
		d.Log.Info("device registered", "uid", uid)
	}

	// Issue a pairing code if the device asked for one. The Registered
	// reply carries the code so the operator can read it out loud.
	// Pairing.Release fires on disconnect so the code is freed
	// promptly (rather than waiting for TTL).
	conn.WantsCode = regMsg.WantCode
	reply := wire.Registered{Type: "registered"}
	// Same table for every device, so nothing about this one is implied
	// by what it receives. nil-safe on a nil Tracker.
	reply.Versions = d.Releases.Latest()
	if regMsg.WantCode && d.Pairing != nil {
		reply.Code = d.Pairing.Issue(uid)
		d.Log.Info("issued pairing code", "uid", uid, "code", reply.Code)
		defer d.Pairing.Release(uid)
	}
	_ = conn.SendJSON(reply)

	defer func() {
		d.Devices.Remove(uid, conn)
		d.Log.Info("device disconnected",
			"uid", uid,
			"duration_s", int(time.Since(connectAt).Seconds()))
	}()

	d.deviceRelay(conn)
}

// authenticateDevice reads and validates the device's register message.
// Returns the register message on success.
//
// The server enforces UID == hash(pubkey) for routing integrity. It does NOT
// challenge the device to prove possession of the private key — the
// browser-side bidirectional verify catches imposters end-to-end (an attacker
// who claims a UID with someone else's pubkey cannot decrypt the encrypted
// fingerprint+nonce payload and so cannot complete a session).
func (d *Deps) authenticateDevice(uid string, conn *registry.DeviceConn) (*wire.Register, error) {
	if !identity.ValidateUID(uid) {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Invalid UID format"})
		return nil, errors.New("invalid uid")
	}

	// Read register message.
	var reg wire.Register
	if err := readJSON(conn.WS, &reg); err != nil {
		return nil, err
	}
	if reg.Type != "register" {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Expected register message"})
		return nil, errors.New("expected register")
	}

	if reg.Protocol < wire.MinProtocolVersion {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "protocol_too_old"})
		return nil, errors.New("protocol too old")
	}

	if reg.PublicKey == "" {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Missing public_key"})
		return nil, errors.New("missing public_key")
	}

	pubKey, pubDER, err := identity.ParsePublicKeyB64(reg.PublicKey)
	if err != nil {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Invalid public_key format"})
		return nil, err
	}

	if identity.UIDFromPublicKeyBytes(pubDER) != uid {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "UID does not match public key"})
		return nil, errors.New("uid mismatch")
	}

	if msg := identity.ValidatePublicKey(pubKey); msg != "" {
		d.Log.Warn("device rejected key", "uid", uid, "reason", msg)
		_ = conn.SendJSON(wire.Error{Type: "error", Message: msg})
		return nil, errors.New(msg)
	}

	return &reg, nil
}

// deviceRelay reads messages from the device. Most are relayed to the
// client named in client_id; a few are about the device itself and are
// answered here, before the lookup that requires one.
//
// Runs until the WS closes or an unrecoverable error occurs.
func (d *Deps) deviceRelay(conn *registry.DeviceConn) {
	for {
		_, data, err := conn.WS.ReadMessage()
		if err != nil {
			return
		}

		var env wire.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			d.Log.Warn("device sent invalid JSON", "uid", conn.UID, "err", err)
			continue
		}

		// Device-scoped messages are about the device itself and carry no
		// client_id, so they are answered before the relay lookup below
		// drops anything that names no client.
		if env.Type == "renew_code" {
			// Issue is idempotent inside the code's lifetime and mints a
			// fresh one past it, so one message covers both cases and
			// both are what the operator wants: read the live code out
			// again, or get another once it has gone.
			//
			// Only answered for a device that asked for a code at
			// register time. One that did not is not in the pairing
			// table, and quietly enrolling it here would turn this
			// message into a way around --nocode.
			reply := wire.CodeIssued{Type: "code_issued"}
			if conn.WantsCode && d.Pairing != nil {
				reply.Code = d.Pairing.Issue(conn.UID)
				d.Log.Info("reissued pairing code", "uid", conn.UID, "code", reply.Code)
			}
			_ = conn.SendJSON(reply)
			continue
		}

		client, ok := d.Clients.Get(env.ClientID)
		if !ok {
			d.Log.Warn("client not found", "uid", conn.UID, "client_id", env.ClientID, "msg_type", env.Type)
			continue
		}

		switch env.Type {
		case "offer":
			var offer wire.Offer
			if err := json.Unmarshal(data, &offer); err != nil {
				d.Log.Warn("device sent invalid offer", "uid", conn.UID, "err", err)
				continue
			}
			// Single-phase ICE: stamp TURN credentials on the offer up
			// front (capacity-gated at allocate time, via CredentialsFor).
			// The connector gathers host + srflx + relay but delays
			// trickling its relay candidate by ~messageTimeoutMs, so a
			// direct pair settles first and relay is only used on fallback
			// — with no ice_restart round trip. !relay just tells the
			// connector to skip that delay; the server stamps creds either
			// way. The device side stays STUN-only (single relay).
			servers, unavailable := d.iceForClient(conn, env.ClientID, false)
			offer.ICEServers = servers
			offer.TURNUnavailable = unavailable
			// Hand the browser the device's pubkey alongside the SDP so it
			// can verify hash(pubkey) == uid and encrypt the
			// bidirectional-verify payload without a separate round trip.
			offer.DevicePubkey = conn.PublicKey
			_ = client.SendJSON(offer)
			d.Log.Info("forwarded offer",
				"from", conn.UID, "to", env.ClientID, "streams", offer.Streams)

		case "answer":
			// Forward verbatim — only thing the client cares about is sdp + client_id.
			_ = client.SendJSON(json.RawMessage(data))
			d.Log.Debug("forwarded answer", "from", conn.UID, "to", env.ClientID)

		case "candidate":
			_ = client.SendJSON(json.RawMessage(data))
			d.Log.Debug("forwarded candidate", "from", conn.UID, "to", env.ClientID)

		case "pair_approved", "pair_rejected":
			// Pairing outcomes: forward verbatim to the originating
			// connector. The device validated the SAS out-of-band and
			// is informing the connector to either save UID/access_code
			// (approved) or abort (rejected).
			_ = client.SendJSON(json.RawMessage(data))
			d.Log.Info("forwarded "+env.Type, "from", conn.UID, "to", env.ClientID)

		default:
			d.Log.Warn("device sent unknown message type", "uid", conn.UID, "type", env.Type)
		}
	}
}

// iceForClient returns (servers, turnUnavailable) for the given target device
// + client pair.
//
// Priority:
//  1. Device-supplied ICE override (BYO TURN) always wins — the operator
//     configured it deliberately, and withholding would defeat the purpose.
//  2. If withhold is true, return STUN-only (no relay allocation). Under
//     single-phase ICE this is the device side: the device never allocates
//     its own relay — it rides the connector's relay (single relay) — so it
//     only ever needs host + srflx. The pairing handshake also uses this.
//  3. Otherwise (the connector's offer relay), call the TURN provider for
//     server-managed credentials, stamped on the offer up front and
//     capacity-gated at allocate time.
func (d *Deps) iceForClient(device *registry.DeviceConn, clientID string, withhold bool) ([]wire.ICEServer, bool) {
	if len(device.ICEServers) > 0 {
		return device.ICEServers, false
	}
	if withhold {
		// STUN only: gather host + srflx, allocate no relay. The connector
		// (which got TURN creds on the offer) does all the relay allocation;
		// this side rides it.
		return d.TURN.StunServers(), false
	}
	return d.TURN.CredentialsFor(clientID)
}

// readJSON reads a single WS message and parses it into v.
func readJSON(ws *websocket.Conn, v any) error {
	_, data, err := ws.ReadMessage()
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return errors.New("invalid json")
	}
	return json.Unmarshal(data, v)
}

// setReadKeepalive configures the read deadline + pong handler so idle
// connections are dropped after PongWait without a pong from the peer.
// Matches Python's websocket_ping_interval=60 + keep_alive_timeout=300.
func (d *Deps) setReadKeepalive(ws *websocket.Conn) {
	wait := d.PongWait
	if wait == 0 {
		wait = 300 * time.Second
	}
	_ = ws.SetReadDeadline(time.Now().Add(wait))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(wait))
		return nil
	})
}

// startPingLoop launches a goroutine that sends ping control frames every
// PingInterval. The peer's pong response resets the read deadline (see
// SetPongHandler in setReadKeepalive); without this loop, idle connections
// silently drop at PongWait even though the peer is alive. The goroutine
// exits when WriteControl returns an error (i.e. the WS has been closed).
//
// Note: gorilla/websocket does NOT auto-send pings — unlike Python's
// websockets library — so the application has to drive the keepalive.
func (d *Deps) startPingLoop(ws *websocket.Conn) {
	interval := d.PingInterval
	if interval == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			err := ws.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(10*time.Second),
			)
			if err != nil {
				return
			}
		}
	}()
}

// shortClientID strips the device UID prefix for log brevity.
func shortClientID(clientID string) string {
	if i := strings.IndexByte(clientID, '_'); i >= 0 {
		return clientID[i+1:]
	}
	return clientID
}
