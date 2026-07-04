package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/registry"
	"bitbang-server-go/internal/wire"
)

// ClientWS handles /ws/client/<uid>.
//
// Flow: assign client_id → register → if target device not found, sleep 3s
// then close with error → otherwise enter relay loop forwarding
// request/answer/candidate to the target device.
func (d *Deps) ClientWS(w http.ResponseWriter, r *http.Request, targetUID string) {
	ip := d.clientIP(r)
	if !d.Limiter.Allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	ws, err := d.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	d.setReadKeepalive(ws)
	d.startPingLoop(ws)

	clientID := targetUID + "_" + shortRandomHex(4)
	connectAt := time.Now()
	conn := &registry.ClientConn{
		ClientID:  clientID,
		TargetUID: targetUID,
		WS:        ws,
		ConnectAt: connectAt,
		BrowserIP: ip,
	}
	d.Clients.Add(conn)
	d.Log.Info("client connected", "client_id", clientID, "target", targetUID)

	defer func() {
		d.Clients.Remove(clientID)
		d.TURN.Release(clientID)
		d.Log.Info("client disconnected", "client_id", clientID,
			"duration_s", int(time.Since(connectAt).Seconds()))
	}()

	// Device-not-found case: slow UID enumeration with a 3-second delay,
	// then send "Device not found" and close. Matches Python signaling.py:413.
	if _, ok := d.Devices.Get(targetUID); !ok {
		time.Sleep(3 * time.Second)
		_ = conn.SendJSON(wire.Error{Type: "error", Message: "Device not found"})
		return
	}

	d.clientRelay(conn)
}

// clientRelay reads messages from the client and forwards to its target device.
// Adds client_id to every forwarded message; attaches ice_servers on request.
func (d *Deps) clientRelay(conn *registry.ClientConn) {
	for {
		_, data, err := conn.WS.ReadMessage()
		if err != nil {
			return
		}

		// Parse generically to preserve any forward-compatible fields.
		var msg map[string]any
		if err := json.Unmarshal(data, &msg); err != nil {
			d.Log.Warn("client sent invalid JSON", "client_id", conn.ClientID, "err", err)
			continue
		}

		// Stamp client_id on every outbound message. Devices use it to
		// route the response back to this specific client.
		msg["client_id"] = conn.ClientID

		msgType, _ := msg["type"].(string)

		device, ok := d.Devices.Get(conn.TargetUID)
		if !ok {
			// Device disappeared mid-session. Inform client and close.
			_ = conn.SendJSON(wire.Error{Type: "error", Message: "Device not found"})
			return
		}

		switch msgType {
		case "request":
			// Telemetry denominator. Counts every "request" arriving here,
			// regardless of how it ends up — the success counts (direct /
			// relay / tcp-relay) and the failure count are client-reported
			// via connection_path, and this is what they normalize against.
			d.Metrics.IncRequests()

			// Capture the browser's !relay flag so the offer relay later
			// knows whether to attach TURN credentials to the offer it
			// forwards back to the client. Once set on the conn, it's
			// stable for the session.
			if forceRelay, ok := msg["force_relay"].(bool); ok && forceRelay {
				conn.ForceRelay = true
			}
			// Stamp ICE servers for the device side. Withhold is always
			// true here: the architecture is browser-only TURN allocation,
			// so the device never needs server-managed TURN credentials.
			// BYO TURN (device-supplied at register) still flows through —
			// iceForClient's first check honors device.ICEServers regardless
			// of withhold.
			servers, _ := d.iceForClient(device, conn.ClientID, true)
			if len(servers) > 0 {
				msg["ice_servers"] = servers
			} else {
				delete(msg, "ice_servers")
			}
			// Stamp the connecting browser's IP so the device can attribute
			// bad-code attempts. Browsers can't set browser_ip themselves
			// (the field is server-supplied); any value the client sent is
			// overwritten here.
			if conn.BrowserIP != "" {
				msg["browser_ip"] = conn.BrowserIP
			} else {
				delete(msg, "browser_ip")
			}
			if err := device.SendJSON(msg); err != nil {
				d.Log.Warn("forward request failed", "client_id", conn.ClientID, "target", conn.TargetUID, "err", err)
				_ = conn.SendJSON(wire.Error{Type: "error", Message: "Device not found"})
				return
			}
			d.Log.Info("forwarded request",
				"client_id", conn.ClientID,
				"target", conn.TargetUID,
				"force_relay", conn.ForceRelay)

		case "answer":
			if err := device.SendJSON(msg); err != nil {
				_ = conn.SendJSON(wire.Error{Type: "error", Message: "Device not found"})
				return
			}
			d.Log.Debug("forwarded answer", "client_id", conn.ClientID, "target", conn.TargetUID)

		case "candidate":
			if err := device.SendJSON(msg); err != nil {
				// Match Python: silently drop candidate if device is gone.
				return
			}
			d.Log.Debug("forwarded candidate", "client_id", conn.ClientID, "target", conn.TargetUID)

		case "connection_path":
			// Fire-and-forget telemetry: the client reports the path of an
			// established (or failed) ICE connection. We bump the matching
			// counter and move on — no reply, no per-client state. One
			// message per ICE establishment, including post-restart
			// re-establishments, so reconnects naturally aggregate.
			//
			// Telemetry contract — connector-only: only the side that sent
			// "request" (browser opening bitba.ng/<uid>, CLI running
			// `bitbang connect`) emits this; the listener never does. The
			// server can't dedupe per session, so if both sides reported
			// every counter would double. Each connector implementation is
			// expected to wire one report per ICE establishment, including
			// restartIce-driven re-establishments. Path values: "direct"
			// (host/srflx both ends), "relay" (UDP TURN), "tcp-relay"
			// (TCP TURN, worst case), "failed" (ICE/DTLS/verify abort).
			path, _ := msg["path"].(string)
			d.Metrics.IncPath(path)
			if path == "failed" {
				// Reason is optional and only meaningful on failures.
				// Logged at info — useful for spotting NAT/firewall
				// trouble at the population level.
				reason, _ := msg["reason"].(string)
				d.Log.Info("client reported failed connection",
					"client_id", conn.ClientID,
					"target", conn.TargetUID,
					"reason", reason)
			} else {
				d.Log.Debug("client reported connection path",
					"client_id", conn.ClientID, "path", path)
			}

		default:
			d.Log.Warn("client sent unknown message type", "client_id", conn.ClientID, "type", msgType)
		}
	}
}

// shortRandomHex returns 2*n hex chars from crypto/rand. Used to suffix
// client IDs so they're unique within a UID's client set.
func shortRandomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// Vanishingly unlikely; fall back to a time-based string.
		return "00000000"
	}
	return hex.EncodeToString(buf)
}

// clientIP returns the connecting peer's IP. Used both for stamping
// browser_ip on relayed "request" messages and for keying the per-IP
// rate limiter — anything that needs to identify "who is calling."
//
// When TrustProxyHeaders is set, X-Real-IP takes precedence over
// r.RemoteAddr. The port is stripped in both cases.
//
// X-Forwarded-For is deliberately NOT consulted: our nginx sets
// X-Real-IP (unspoofable, equal to nginx's TCP-level $remote_addr) but
// does not set XFF, so any XFF that arrives is whatever the client
// sent — i.e. spoofable. If a multi-hop LB is added later this can
// be revisited, with the chain-walking logic that scheme actually
// requires.
//
// TrustProxyHeaders must only be enabled when the upstream proxy is
// known to set X-Real-IP itself. The fallback (RemoteAddr) is always
// safe.
func (d *Deps) clientIP(r *http.Request) string {
	if d.TrustProxyHeaders {
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return strings.TrimSpace(real)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// closeWith sends a close frame to ws with the given code/reason. Best effort.
func closeWith(ws *websocket.Conn, code int, reason string) {
	_ = ws.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(time.Second),
	)
}
