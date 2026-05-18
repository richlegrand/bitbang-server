package handler

import (
	"encoding/json"
	"net/http"

	"bitbang-server-go/internal/wire"
)

// Status payload — field names and shape match Python signaling.py:144-154.
type statusResp struct {
	Version           string `json:"version"`
	Protocol          int    `json:"protocol"`
	MinProtocol       int    `json:"min_protocol"`
	Devices           int    `json:"devices"`
	Clients           int    `json:"clients"`
	ActiveTURNClients int    `json:"active_turn_clients"`
	TURNMaxActive     int    `json:"turn_max_active"`
}

const Version = "0.1.0"

// Status handles GET /status.
func (d *Deps) Status(w http.ResponseWriter, r *http.Request) {
	resp := statusResp{
		Version:           Version,
		Protocol:          wire.ProtocolVersion,
		MinProtocol:       wire.MinProtocolVersion,
		Devices:           d.Devices.Count(),
		Clients:           d.Clients.Count(),
		ActiveTURNClients: d.TURN.ActiveCount(),
		TURNMaxActive:     d.TURN.MaxActive(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
