package handler

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"

	"bitbang-server-go/internal/metrics"
	"bitbang-server-go/internal/wire"
)

// Status payload. Field names and shape are inherited from the original
// Python signaling server,
// minus the TURN-client counters (active_turn_clients / turn_max_active),
// which were dropped: the count tracked TURN grants, not actual relay paths,
// so it was misleading and of unclear value. Replaced (in spirit) by the
// embedded metrics.Snapshot below, which reports actual session paths from
// client-side telemetry — those numbers reflect what really happened, not
// what credentials we handed out.
type statusResp struct {
	Version     string `json:"version"`
	Protocol    int    `json:"protocol"`
	MinProtocol int    `json:"min_protocol"`
	Devices     int    `json:"devices"`
	Clients     int    `json:"clients"`
	ActiveCodes int    `json:"active_codes"`

	// Embed Snapshot inline so its JSON tags (connection_requests_total,
	// connections_direct_total, ...) sit at the top level of the response
	// alongside the existing fields, rather than nested under a "metrics"
	// key. Consumers (the live /status page, scrape jobs) can compute
	// success / direct ratios directly from a single flat object.
	metrics.Snapshot
}

const Version = "0.1.0"

// fromLoopback reports whether the caller reached us on the loopback
// interface rather than through the public listener.
//
// This has to go through clientIP, not r.RemoteAddr. Production runs
// nginx on the same host, so *every* proxied request has a loopback
// RemoteAddr -- reading it directly would exempt the entire internet.
// clientIP prefers nginx's X-Real-IP when TrustProxyHeaders is set, and
// nginx overwrites that header on every request, so a caller cannot
// claim to be local. X-Forwarded-For, which a caller can set, is not
// consulted by clientIP at all.
//
// What survives the check is a request that never went through nginx:
// the deploy script curling http://localhost:PORT/status over ssh.
func (d *Deps) fromLoopback(r *http.Request) bool {
	ip := net.ParseIP(d.clientIP(r))
	return ip != nil && ip.IsLoopback()
}

// statusAllowed reports whether this request may read /status.
//
// An unset token leaves the endpoint public. Otherwise the caller needs
// the bearer token -- except on loopback, where the deploy script reads
// it over ssh and a token would guard nothing that a shell on the host
// does not already grant.
func (d *Deps) statusAllowed(r *http.Request) bool {
	if d.StatusToken == "" || d.fromLoopback(r) {
		return true
	}
	got := r.Header.Get("Authorization")
	want := "Bearer " + d.StatusToken
	// Constant time so the token cannot be recovered a byte at a time.
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Status handles GET /status.
func (d *Deps) Status(w http.ResponseWriter, r *http.Request) {
	if !d.statusAllowed(r) {
		// 404 rather than 401: a prober learns nothing about whether the
		// endpoint exists, and there is no auth flow to advertise.
		http.NotFound(w, r)
		return
	}
	resp := statusResp{
		Version:     Version,
		Protocol:    wire.ProtocolVersion,
		MinProtocol: wire.MinProtocolVersion,
		Devices:     d.Devices.Count(),
		Clients:     d.Clients.Count(),
		Snapshot:    d.Metrics.Snapshot(),
	}
	if d.Pairing != nil {
		resp.ActiveCodes = d.Pairing.ActiveCount()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
