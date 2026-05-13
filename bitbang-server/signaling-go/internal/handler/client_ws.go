package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
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
	if !d.Limiter.Allow(r.RemoteAddr) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	ws, err := d.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	d.setReadKeepalive(ws)

	clientID := targetUID + "_" + shortRandomHex(4)
	connectAt := time.Now()
	conn := &registry.ClientConn{
		ClientID:  clientID,
		TargetUID: targetUID,
		WS:        ws,
		ConnectAt: connectAt,
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
			// Capacity-decide once at request time (CredentialsFor caches
			// internally so the offer-forward path sees the same answer).
			servers, unavailable := d.iceForClient(device, conn.ClientID)
			if len(servers) > 0 {
				msg["ice_servers"] = servers
			}
			if err := device.SendJSON(msg); err != nil {
				d.Log.Warn("forward request failed", "client_id", conn.ClientID, "target", conn.TargetUID, "err", err)
				_ = conn.SendJSON(wire.Error{Type: "error", Message: "Device not found"})
				return
			}
			d.Log.Info("forwarded request",
				"client_id", conn.ClientID,
				"target", conn.TargetUID,
				"turn", turnStatus(device, conn.ClientID, unavailable, d.TURN.Configured()))

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

		default:
			d.Log.Warn("client sent unknown message type", "client_id", conn.ClientID, "type", msgType)
		}
	}
}

// turnStatus picks a short string for the request-forwarded log line that
// matches the Python implementation's log vocabulary.
func turnStatus(device *registry.DeviceConn, clientID string, unavailable bool, turnConfigured bool) string {
	if unavailable {
		return "STUN only (at capacity)"
	}
	if len(device.ICEServers) > 0 {
		return "with device-supplied ICE"
	}
	if !turnConfigured {
		return "direct only (no TURN credentials)"
	}
	return "with TURN"
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

// closeWith sends a close frame to ws with the given code/reason. Best effort.
func closeWith(ws *websocket.Conn, code int, reason string) {
	_ = ws.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(time.Second),
	)
}
