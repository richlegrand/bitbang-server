package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"bitbang-server-go/internal/registry"
	"bitbang-server-go/internal/wire"
)

// pairInflight is a per-IP semaphore on active /ws/pair connections.
// The 3-second LookupDelay inside pairing.Table.Lookup is the per-
// connection brake; this semaphore is the cross-connection brake.
// Without it, an attacker who opens N parallel /ws/pair WebSockets
// from one IP amplifies the lookup rate N-fold and can scan the 10⁶
// code space in proportionally less time. Capping at one in-flight
// pair attempt per IP restores the intended ~28k lookups/day/IP
// ceiling, while still letting a real user pair (which is a one-at-
// a-time operation by nature).
//
// A real operator deployment will also have a reverse-proxy rate
// limiter at the ingress; this is a defense-in-depth backstop so the
// server is safe-by-default even if Limiter is NoOp.
var (
	pairInflightMu sync.Mutex
	pairInflight   = map[string]int{}
)

// acquirePairSlot reserves an in-flight slot for ip. Returns false if
// the IP already has one open — the caller should reject the connection.
// release must be called on every successful acquire.
func acquirePairSlot(ip string) bool {
	pairInflightMu.Lock()
	defer pairInflightMu.Unlock()
	if pairInflight[ip] > 0 {
		return false
	}
	pairInflight[ip]++
	return true
}

func releasePairSlot(ip string) {
	pairInflightMu.Lock()
	defer pairInflightMu.Unlock()
	if pairInflight[ip] > 1 {
		pairInflight[ip]--
	} else {
		delete(pairInflight, ip)
	}
}

// PairWS handles /ws/pair — the connector-side entry point for code
// exchange. The first message on the WebSocket must be a wire.PairInit
// with a 6-digit code. The server:
//
//  1. Sleeps for the pairing-table's built-in lookup delay (3s,
//     constant-time, regardless of whether the code is valid). This is
//     the per-connection brake on enumeration; per-IP rate limiting at
//     the WS upgrade is the cross-connection brake (handled by
//     d.Limiter).
//  2. Looks up the code. Unknown / expired → respond with Error
//     {Message:"unknown_code"} and close. The error is sent only after
//     the delay so timing doesn't leak whether the code existed.
//  3. Resolves the target UID, looks up the device's live WS, and
//     forwards a PairRequest to it with the assigned client_id.
//  4. Sends PairRouted back to the connector and enters the standard
//     client relay loop. From this point the connection behaves like a
//     normal /ws/client/<uid> session, except the device runs the SAS
//     prompt before sending application traffic.
//
// PairWS shares wire format with the existing client relay so the
// device's offer/answer/candidate handling needs no change — the
// device just sees one more event type on the same WS.
func (d *Deps) PairWS(w http.ResponseWriter, r *http.Request) {
	ip := d.clientIP(r)
	if !d.Limiter.Allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	if d.Pairing == nil {
		http.Error(w, "pairing disabled", http.StatusNotFound)
		return
	}

	if !acquirePairSlot(ip) {
		// Concurrent pair attempt from same IP. Refuse before
		// upgrading so the attacker doesn't even get a WebSocket.
		http.Error(w, "pair_inflight", http.StatusTooManyRequests)
		return
	}
	defer releasePairSlot(ip)

	ws, err := d.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	d.setReadKeepalive(ws)
	d.startPingLoop(ws)

	// First (and only) message before normal relay: PairInit. We use a
	// short read deadline here so an idle WS doesn't park a goroutine
	// forever; the established session resets the deadline via the
	// keepalive helper.
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var init wire.PairInit
	if err := readJSON(ws, &init); err != nil {
		return
	}
	if init.Type != "pair_init" || init.Code == "" {
		// Honor the same delay we'd apply to a real lookup so timing
		// of "malformed message" matches "unknown code".
		time.Sleep(3 * time.Second)
		_ = sendJSON(ws, wire.Error{Type: "error", Message: "unknown_code"})
		return
	}

	// Lookup blocks for 3s by design (LookupDelay). Resets the read
	// deadline for the rest of the session afterwards.
	uid := d.Pairing.Lookup(init.Code)
	d.setReadKeepalive(ws)
	if uid == "" {
		_ = sendJSON(ws, wire.Error{Type: "error", Message: "unknown_code"})
		d.Log.Info("pair_init unknown code", "remote", ip)
		return
	}

	device, ok := d.Devices.Get(uid)
	if !ok {
		// Device disconnected between code issuance and this lookup.
		_ = sendJSON(ws, wire.Error{Type: "error", Message: "Device not found"})
		d.Log.Info("pair_init device gone", "uid", uid, "remote", ip)
		return
	}

	// Standard client-side bookkeeping: client_id, register with the
	// ClientRegistry, defer cleanup.
	clientID := uid + "_" + shortRandomHex(4)
	connectAt := time.Now()
	conn := &registry.ClientConn{
		ClientID:  clientID,
		TargetUID: uid,
		WS:        ws,
		ConnectAt: connectAt,
		BrowserIP: ip,
	}
	d.Clients.Add(conn)
	d.Log.Info("client paired",
		"client_id", clientID, "target", uid, "code", init.Code, "remote", ip)

	defer func() {
		d.Clients.Remove(clientID)
		d.TURN.Release(clientID)
		d.Log.Info("client disconnected",
			"client_id", clientID, "duration_s", int(time.Since(connectAt).Seconds()))
	}()

	// Tell the device to expect this connector — same shape as a
	// regular "request" but typed pair_request so the device can run
	// the SAS confirmation flow instead of going straight to ready.
	pr := wire.PairRequest{Type: "pair_request", ClientID: clientID}
	if err := device.SendJSON(pr); err != nil {
		_ = sendJSON(ws, wire.Error{Type: "error", Message: "Device not found"})
		return
	}

	// Acknowledge to the connector so the browser knows it's safe to
	// start consuming offer/candidate messages.
	_ = sendJSON(ws, wire.PairRouted{Type: "pair_routed"})

	// Hand off to the standard client relay. The offer/answer/candidate
	// flow is identical to a non-paired client; only the post-DTLS
	// behavior on the device differs.
	d.clientRelay(conn)
}

// sendJSON writes one JSON message directly to a WebSocket. Used in
// the pre-relay phase where we don't yet have a registry.ClientConn.
func sendJSON(ws interface {
	WriteMessage(int, []byte) error
}, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ws.WriteMessage(1 /* websocket.TextMessage */, b)
}
