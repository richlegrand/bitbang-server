// Package handler implements the HTTP and WebSocket endpoints of the
// signaling server. Behaviors mirror the Python implementation in
// ~/bitbang-server/bitbang-server/signaling/signaling.py — wire-compatible
// behavior is the contract.
package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/identity"
	"bitbang-server-go/internal/ratelimit"
	"bitbang-server-go/internal/registry"
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
	Log     *slog.Logger

	// Upgrader is the gorilla websocket upgrader, configured once.
	Upgrader websocket.Upgrader

	// PingInterval / PongWait control the keepalive cycle. Match Python:
	// websocket_ping_interval=60, keep_alive_timeout=300.
	PingInterval time.Duration
	PongWait     time.Duration
}

// DeviceWS handles /ws/device/<uid>.
//
// Flow: upgrade → authenticate (register/challenge/challenge_response) →
// preempt prior connection (if any) → register → enter relay loop.
func (d *Deps) DeviceWS(w http.ResponseWriter, r *http.Request, uid string) {
	if !d.Limiter.Allow(r.RemoteAddr) {
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
		d.Log.Warn("device auth failed", "uid", uid, "remote", r.RemoteAddr, "err", err)
		return
	}

	// Preempt any existing connection for this UID. The new connection has
	// proven key ownership, so it takes precedence (typically a device
	// restart racing with its own stale ws).
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

	_ = conn.SendJSON(wire.Registered{Type: "registered"})

	defer func() {
		d.Devices.Remove(uid, conn)
		d.Log.Info("device disconnected",
			"uid", uid,
			"duration_s", int(time.Since(connectAt).Seconds()))
	}()

	d.deviceRelay(conn)
}

// authenticateDevice runs the register → challenge → challenge_response
// sequence. Returns the register message on success.
// Error strings sent to the client match Python signaling.py exactly.
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

	// Issue challenge.
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	_ = conn.SendJSON(wire.Challenge{
		Type:  "challenge",
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]),
	})

	var resp wire.ChallengeResponse
	if err := readJSON(conn.WS, &resp); err != nil {
		return nil, err
	}
	if resp.Type != "challenge_response" {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Expected challenge_response"})
		return nil, errors.New("expected challenge_response")
	}

	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Invalid signature format"})
		return nil, err
	}

	if err := identity.VerifySignature(pubKey, nonce[:], sig); err != nil {
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Invalid signature"})
		return nil, err
	}

	return &reg, nil
}

// deviceRelay reads messages from the device and forwards to the target client.
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
			servers, unavailable := d.iceForClient(conn, env.ClientID)
			offer.ICEServers = servers
			offer.TURNUnavailable = unavailable
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

		default:
			d.Log.Warn("device sent unknown message type", "uid", conn.UID, "type", env.Type)
		}
	}
}

// iceForClient returns (servers, turnUnavailable) for the given target device
// + client pair. Device-supplied ICE override beats coturn; otherwise the
// TURN provider decides.
func (d *Deps) iceForClient(device *registry.DeviceConn, clientID string) ([]wire.ICEServer, bool) {
	if len(device.ICEServers) > 0 {
		return device.ICEServers, false
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
