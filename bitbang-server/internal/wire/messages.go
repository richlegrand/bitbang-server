// Package wire defines the JSON message types exchanged between the
// signaling server and devices/clients over WebSocket.
//
// All messages are JSON objects with a "type" string discriminator.
// Unknown fields are tolerated on inbound messages (forward compatibility);
// outbound messages set only the fields the protocol requires.
package wire

// Protocol versioning. Devices send their supported version in the register
// message; the server rejects anything below MinProtocolVersion.
//
// v3 introduces split-identity URLs: the wire UID is 128 bits encoded as
// 22 base64url chars (no padding), and the URL fragment carries a 64-bit
// access code (11 base64url chars) that the browser includes inside the
// encrypted_request payload. The server also forwards the connecting
// browser's IP on relayed "request" messages so the device can attribute
// bad-code attempts.
const (
	ProtocolVersion    = 3
	MinProtocolVersion = 3
)

// ICEServer is the browser-native ice_servers format (one entry per server).
// URLs may be a single string or a list — we always use a list here so the
// JSON serialization is predictable. Username and credential are present
// only on TURN entries.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Register is the first message a device sends after the WS opens.
// PublicKey is base64-encoded DER (SubjectPublicKeyInfo). The algorithm is
// derived from the DER structure itself, not carried in a separate field.
//
// WantCode (additive in v3.x) opts the device into the code-exchange
// pairing flow. When set, the server allocates a 6-digit code, stores
// the code→UID mapping, and includes the code in the Registered reply.
// Connectors can then pair by sending PairInit with that code instead
// of needing the full 22-char UID up front. Devices that don't speak
// code exchange omit the field; the server defaults to legacy behavior.
type Register struct {
	Type       string      `json:"type"` // "register"
	Protocol   int         `json:"protocol"`
	PublicKey  string      `json:"public_key"`
	ICEServers []ICEServer `json:"ice_servers,omitempty"` // device-supplied override
	WantCode   bool        `json:"want_code,omitempty"`
}

// Registered is sent by the server after a successful register. Code is
// populated only when the device sent WantCode=true (and pairing is
// enabled server-side); legacy devices that don't set WantCode get a
// bare {"type":"registered"} reply.
type Registered struct {
	Type string `json:"type"`           // "registered"
	Code string `json:"code,omitempty"` // 6-digit pairing code
}

// Error is sent by the server when any validation/auth step fails.
type Error struct {
	Type    string `json:"type"`    // "error"
	Message string `json:"message"` // short error string
}

// Offer is a WebRTC offer SDP relayed between device and client.
// When device→server, the device's offer includes streams (mid→name).
// When server→client, the server attaches ice_servers, turn_unavailable, and
// device_pubkey. device_pubkey is the base64 DER SubjectPublicKeyInfo the
// device presented at register time; the browser checks
// hash(device_pubkey) == uid and uses the key to encrypt the
// bidirectional-verify payload that rides on the answer.
type Offer struct {
	Type            string            `json:"type"` // "offer"
	SDP             string            `json:"sdp"`
	ClientID        string            `json:"client_id"`
	Streams         map[string]string `json:"streams,omitempty"`
	ICEServers      []ICEServer       `json:"ice_servers,omitempty"`
	TURNUnavailable bool              `json:"turn_unavailable,omitempty"`
	DeviceName      string            `json:"device_name,omitempty"`
	DevicePubkey    string            `json:"device_pubkey,omitempty"`
}

// Answer is a WebRTC answer SDP relayed between client and device. The
// browser is the answerer in this protocol, so the answer is also where the
// browser delivers its bidirectional-verify payload — base64 ciphertext of
// {fingerprint, nonce} encrypted to the device's public key. Opaque to the
// server; relayed verbatim to the device.
type Answer struct {
	Type             string `json:"type"` // "answer"
	SDP              string `json:"sdp"`
	ClientID         string `json:"client_id"`
	EncryptedRequest string `json:"encrypted_request,omitempty"`
}

// Candidate is a WebRTC ICE candidate relayed between client and device.
// The candidate field is browser-native (object with candidate/sdpMid/sdpMLineIndex).
type Candidate struct {
	Type          string `json:"type"` // "candidate"
	Candidate     any    `json:"candidate"`
	SDPMLineIndex any    `json:"sdp_mline_index,omitempty"`
	SDPMid        any    `json:"sdp_mid,omitempty"`
	ClientID      string `json:"client_id"`
}

// Request is sent by a client to initiate a session with a device.
// The server augments it with client_id, ice_servers, and browser_ip
// before forwarding. browser_ip is the connecting browser's IP as seen by
// the signaling server (X-Real-IP when behind a reverse proxy, else the
// direct RemoteAddr). Devices use it to attribute bad-code attempts; the
// browser never sets it itself.
//
// ForceRelay is set by the browser when the URL carries the ?relay
// query-string flag. It tells the server to skip TURN withholding and
// include relay credentials in the initial offer (the legacy behavior
// before TURN withholding shipped). Used for debugging and end-to-end
// TURN verification.
type Request struct {
	Type       string      `json:"type"` // "request"
	ClientID   string      `json:"client_id,omitempty"`
	ICEServers []ICEServer `json:"ice_servers,omitempty"`
	BrowserIP  string      `json:"browser_ip,omitempty"`
	ForceRelay bool        `json:"force_relay,omitempty"`
}

// RequestICE is sent by a browser when its direct ICE attempt has stalled
// (no `connected` state within the fallback timeout). The server responds
// with an ICEServersPush containing TURN credentials, which the browser
// then injects via pc.setConfiguration + restartIce. The signaling server
// withholds TURN from the initial offer to bias ICE toward direct paths;
// browsers that don't connect directly within the timeout opt back in via
// this message.
type RequestICE struct {
	Type string `json:"type"` // "request_ice"
}

// ICEServersPush carries TURN credentials to a browser after it has
// requested them via RequestICE (or, for ?relay-forced flows, attached
// to the initial offer instead). TURNUnavailable reflects the TURN
// provider's capacity gate — when true, ICEServers is empty and the
// browser should surface a "relay at capacity" banner.
type ICEServersPush struct {
	Type            string      `json:"type"` // "ice_servers"
	ICEServers      []ICEServer `json:"ice_servers,omitempty"`
	TURNUnavailable bool        `json:"turn_unavailable,omitempty"`
}

// PairInit is sent by a connector to a pairing endpoint with a 6-digit
// code. The server looks the code up (with a built-in 3-second delay,
// constant-time regardless of outcome) and either routes onward to the
// owning device as PairRequest, or returns Error{Message:"unknown_code"}.
//
// ForceRelay mirrors the URL flow's `force_relay`: when set, the offer the
// device produces is stamped with TURN credentials up front instead of the
// default STUN-only ICE, so a pairing on a known-hard network skips the
// direct attempt. Wired to the connector's `--relay` flag.
type PairInit struct {
	Type       string `json:"type"` // "pair_init"
	Code       string `json:"code"`
	ForceRelay bool   `json:"force_relay,omitempty"`
}

// PairRouted is sent by the server to the connector once a PairInit
// has been resolved to a device. After this, the connector and device
// exchange the usual offer/answer/candidate messages (relayed by the
// server) over the same WebSocket, identified by client_id.
type PairRouted struct {
	Type string `json:"type"` // "pair_routed"
}

// PairRequest is sent by the server to the device WebSocket when a
// PairInit lookup hits the device's code. The device treats it like a
// regular Request — same handshake — but the post-DTLS flow runs the
// SAS prompt before unlocking application traffic.
//
// RemoteIP is the IP the connector reached us from (X-Real-IP behind
// the reverse proxy, or the direct RemoteAddr otherwise). Useful for
// the device operator's audit log: who's trying to pair right now. Not
// presumptive about the connector being a browser — pair_init may come
// from a CLI, an embedded client, anything.
//
// ICEServers carries the same phase-1 STUN entries the direct flow stamps
// on a Request, so the listener gathers srflx candidates and is reachable
// through NAT — not just on the same LAN. It is STUN-only (the device side
// never gets server-managed TURN; relay allocation is connector-side), so
// it is free and never capacity-gated.
type PairRequest struct {
	Type       string      `json:"type"` // "pair_request"
	ClientID   string      `json:"client_id"`
	RemoteIP   string      `json:"remote_ip,omitempty"`
	ICEServers []ICEServer `json:"ice_servers,omitempty"`
}

// PairApproved is a bare, non-secret "approved" ack the device sends over
// signaling after the operator confirms the out-of-band SAS. The server
// forwards it to the originating connector. The actual credentials
// (uid, public_key, access_code) are delivered peer-to-peer over the
// SAS-verified WebRTC data channel — never over signaling — so the server
// can neither read nor alter them.
type PairApproved struct {
	Type     string `json:"type"` // "pair_approved"
	ClientID string `json:"client_id"`
}

// PairRejected is sent by the device to abort a pairing in progress.
// Reason is one of "user_declined", "sas_mismatch", "timeout".
type PairRejected struct {
	Type     string `json:"type"` // "pair_rejected"
	ClientID string `json:"client_id"`
	Reason   string `json:"reason"`
}

// ConnectionPath is a fire-and-forget telemetry message sent by the
// connecting peer after each ICE establishment, reporting how the
// connection actually ended up. The server bumps a counter; no reply is
// expected.
//
// One message is sent per transition into the ICE "connected" state,
// including re-establishments via restartIce within a single peer
// connection — so a client that reconnects ten times in a row produces
// ten reports, regardless of whether those happened over one PC or many.
//
// # Telemetry contract: connector-only
//
// **Only the connector sends this message; the listener never does.**
//
// The "connector" is the side that initiates the session by sending a
// "request" to /ws/client/<uid> — i.e., a browser opening bitba.ng/<uid>
// or a CLI running `bitbang connect <URL>`. The "listener" is the device
// side that accepts the incoming request (a `bitbang serve …` process,
// a bitbang-python WSGI/ASGI wrapper, etc.).
//
// This rule exists because each session has exactly one connector and
// one listener; if both reported, every counter would double. The server
// has no way to deduplicate reports per session — `connection_path` is
// stateless on this side — so the property must be enforced at the
// emitter.
//
// When adding new code:
//
//   - New connector implementation (browser, CLI, future Python connect
//     helper, embedded SDK) → wire up the same one-report-per-ICE-
//     establishment telemetry. The denominator on the server is the
//     count of "request" messages, so missing reports show up as
//     unaccounted requests in /status.
//   - New listener implementation → do not emit this message. Listener-
//     side connection state is invisible to the metric on purpose.
//
// Path values:
//
//   - "direct"    — selected pair is host or srflx on both ends
//   - "relay"     — selected pair uses a UDP TURN relay
//   - "tcp-relay" — selected pair uses a TCP TURN relay (worst case)
//   - "failed"    — ICE never reached connected, DTLS handshake errored,
//                   or bidirectional verify rejected the peer
//
// Reason is an optional diagnostic string accompanying "failed" — e.g.,
// "ice_timeout", "dtls_failed", "verify_failed". The server doesn't act
// on it today; it's reserved for later breakouts in /status.
type ConnectionPath struct {
	Type   string `json:"type"` // "connection_path"
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

// Envelope is used to peek at the "type" field before fully deserializing.
type Envelope struct {
	Type     string `json:"type"`
	ClientID string `json:"client_id,omitempty"`
}
