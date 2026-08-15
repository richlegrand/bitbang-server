package handler

import (
	"encoding/json"
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

// Status handles GET /status.
func (d *Deps) Status(w http.ResponseWriter, r *http.Request) {
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
