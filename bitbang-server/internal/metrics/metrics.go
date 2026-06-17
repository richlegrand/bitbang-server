// Package metrics holds the small set of counters the signaling server
// exposes via /status. They're deliberately lightweight (process-local
// atomics, no time-series storage, no external dependency) — the goal at
// v1 is "snapshot what's currently observable" rather than "build a
// monitoring system."
//
// Lifecycle: counters reset to zero on process restart. That's acceptable
// for an MVP — if continuity matters later, snapshot /status periodically
// to a flat file or move to Prometheus / a real TSDB where the scrape
// model handles restarts naturally.
//
// The metrics are written from the signaling-message handlers; their
// values feed a couple of derived ratios that justify the architecture
// (direct-vs-relay) and surface operational health (success rate).
package metrics

import (
	"sync/atomic"
)

// Metrics is the process-local counter set. Safe for concurrent use.
//
// The five exported fields are the wire-stable names — they map 1:1 to
// the JSON keys emitted in /status, with `_total` suffixes appended.
// Callers should write through the Inc* helpers rather than the atomic
// types directly, both for symmetry and to keep call sites readable.
type Metrics struct {
	// requests is the count of "request" messages received on
	// /ws/client/<uid>. The denominator for success and failure rates;
	// without it the path counts can't be normalized.
	requests atomic.Int64

	// direct is the count of connection_path reports with
	// path="direct" — sessions that established without TURN.
	direct atomic.Int64

	// relay is the count of connection_path reports with path="relay" —
	// sessions that established over a UDP TURN relay (the common
	// relay-fallback path).
	relay atomic.Int64

	// tcpRelay is the count of connection_path reports with
	// path="tcp-relay" — sessions that fell all the way back to TCP-
	// relayed TURN (typically symmetric NATs / hostile firewalls).
	tcpRelay atomic.Int64

	// failed is the count of connection_path reports with path="failed"
	// — sessions where ICE never reached connected, DTLS errored, or
	// bidirectional verify rejected the peer.
	failed atomic.Int64
}

// New returns a zero-initialized Metrics value ready for concurrent use.
func New() *Metrics {
	return &Metrics{}
}

// IncRequests bumps the requests counter; called once per "request"
// message arriving on the client-side WebSocket relay.
func (m *Metrics) IncRequests() { m.requests.Add(1) }

// IncPath bumps the counter matching path. Unknown path values are
// silently ignored — defensive against a future client reporting a path
// type the server doesn't know about yet. The caller can log the unknown
// value separately if diagnostics matter.
func (m *Metrics) IncPath(path string) {
	switch path {
	case "direct":
		m.direct.Add(1)
	case "relay":
		m.relay.Add(1)
	case "tcp-relay":
		m.tcpRelay.Add(1)
	case "failed":
		m.failed.Add(1)
	}
}

// Snapshot is a point-in-time read of all counters. Used by /status to
// render the response. The fields are atomically read individually but
// the snapshot itself is not a transaction across all counters — that's
// fine, the small inconsistency is invisible at the timescales callers
// care about.
type Snapshot struct {
	Requests int64 `json:"connection_requests_total"`
	Direct   int64 `json:"connections_direct_total"`
	Relay    int64 `json:"connections_relay_total"`
	TCPRelay int64 `json:"connections_tcp_relay_total"`
	Failed   int64 `json:"connections_failed_total"`
}

// Snapshot returns the current counter values.
func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		Requests: m.requests.Load(),
		Direct:   m.direct.Load(),
		Relay:    m.relay.Load(),
		TCPRelay: m.tcpRelay.Load(),
		Failed:   m.failed.Load(),
	}
}
