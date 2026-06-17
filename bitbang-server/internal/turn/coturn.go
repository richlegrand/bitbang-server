// Package turn provides TURN credential generation for clients and the
// capacity-gating logic that decides which clients get TURN vs STUN-only.
//
// The TURNProvider interface is the v1 seam for future multi-host TURN —
// the relay code calls CredentialsFor() and Release(); the provider impl
// decides whether to hand out credentials for one TURN host or many.
package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strconv"
	"sync"
	"time"

	"bitbang-server-go/internal/wire"
)

// TURNProvider is the interface the signaling handlers use to obtain
// ice_servers for a client. Implementations decide capacity gating and
// which TURN host(s) to advertise.
type TURNProvider interface {
	// CredentialsFor returns the ICE servers for clientID. The bool is
	// turnUnavailable: true means "TURN exists but this client is over
	// the capacity gate; the returned servers are STUN-only."
	//
	// Called twice for the same client_id during a session: once at
	// 'request' time (capacity decision) and once at 'offer' time
	// (forwarding to client). Both must return identical creds, so the
	// provider caches per client_id internally.
	CredentialsFor(clientID string) (servers []wire.ICEServer, turnUnavailable bool)

	// StunServers returns STUN-only ICE servers (no credentials), used for
	// the direct-only first connection phase. The browser gathers host +
	// srflx from these and can connect peer-to-peer through both NATs
	// without ever allocating a relay. STUN Binding creates no allocation
	// and is not capacity-gated, so this is free to hand out. Returns nil
	// if no TURN host is configured.
	StunServers() []wire.ICEServer

	// Release frees any cached state for clientID. Called on client
	// disconnect so capacity counters and cred caches don't leak.
	Release(clientID string)

	// ActiveCount returns the number of clients currently granted TURN.
	// Used by /status.
	ActiveCount() int

	// MaxActive returns the configured capacity cap (0 = no cap).
	MaxActive() int

	// Configured reports whether any TURN backend is configured at all.
	Configured() bool
}

// Coturn is a TURNProvider backed by a single coturn host using the
// REST API (RFC 7635) for ephemeral credentials. The host validates
// credentials using the same shared secret — no database needed.
type Coturn struct {
	host      string // e.g. "turn.example.com"
	secret    string
	ttl       int // seconds
	maxActive int // capacity gate; 0 disables

	mu      sync.Mutex
	granted map[string][]wire.ICEServer // client_id -> cached creds (granted TURN)
	gated   map[string]bool             // client_id -> true if at-capacity (STUN-only)
}

// NewCoturn returns a Coturn TURNProvider. If host or secret is empty,
// CredentialsFor returns no servers (TURN disabled mode).
func NewCoturn(host, secret string, ttl, maxActive int) *Coturn {
	return &Coturn{
		host:      host,
		secret:    secret,
		ttl:       ttl,
		maxActive: maxActive,
		granted:   make(map[string][]wire.ICEServer),
		gated:     make(map[string]bool),
	}
}

func (c *Coturn) Configured() bool {
	return c.host != "" && c.secret != ""
}

// CredentialsFor returns the ICE servers for a client. Capacity-gates
// idempotently — repeated calls for the same client return the same answer.
func (c *Coturn) CredentialsFor(clientID string) ([]wire.ICEServer, bool) {
	if !c.Configured() {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Already granted TURN — return cached creds.
	if servers, ok := c.granted[clientID]; ok {
		return servers, false
	}
	// Already gated to STUN-only.
	if c.gated[clientID] {
		return c.StunServers(), true
	}

	// New client: capacity decision.
	if c.maxActive > 0 && len(c.granted) >= c.maxActive {
		c.gated[clientID] = true
		return c.StunServers(), true
	}

	// Grant TURN: generate REST-API credentials.
	servers := c.generateCredentials()
	c.granted[clientID] = servers
	return servers, false
}

func (c *Coturn) Release(clientID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.granted, clientID)
	delete(c.gated, clientID)
}

func (c *Coturn) ActiveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.granted)
}

func (c *Coturn) MaxActive() int {
	return c.maxActive
}

func (c *Coturn) Host() string { return c.host }

// StunServers returns the STUN-only ICE entry for this coturn host, or nil
// if no host is configured. Safe to call under the capacity mutex — it reads
// only the immutable host.
func (c *Coturn) StunServers() []wire.ICEServer {
	if c.host == "" {
		return nil
	}
	return []wire.ICEServer{{URLs: []string{fmt.Sprintf("stun:%s:3478", c.host)}}}
}

// generateCredentials produces a single REST-API credential pair valid for
// TTL seconds. Username is the expiry epoch; password is base64(HMAC-SHA1(secret, username)).
// The credential is structurally identical to what the Python server produces.
func (c *Coturn) generateCredentials() []wire.ICEServer {
	expiry := time.Now().Unix() + int64(c.ttl)
	username := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha1.New, []byte(c.secret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return append(c.StunServers(), wire.ICEServer{
		URLs: []string{
			fmt.Sprintf("turn:%s:3478", c.host),
			fmt.Sprintf("turns:%s:5349", c.host),
		},
		Username:   username,
		Credential: password,
	})
}

// Compile-time check
var _ TURNProvider = (*Coturn)(nil)
