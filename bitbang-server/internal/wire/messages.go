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

	// Boot identifies this run of the firmware: generated once at startup
	// and the same for every reconnection until the device restarts.
	//
	// It is what tells a browser whether its own state is still worth
	// anything. A device that reboots cannot pick up where the last one
	// left off -- the page is holding an iframe rendered by the old
	// firmware, a service worker's session table, stream elements bound to
	// presentations that instance declared, a settings declaration and its
	// revision -- and if the firmware changed, every one of those
	// assumptions is worse rather than better. So a new boot means the page
	// has to reload, and the same boot means it does not.
	//
	// Which is a distinction nothing else here can make. A new device
	// connection does not imply a restart: a wss blip or this server
	// restarting produces one with the firmware still running and every bit
	// of that state still valid. And "I had to renegotiate" does not imply
	// it either -- a relay expiry or a NAT change forces a whole new offer
	// and answer with the device none the wiser.
	//
	// Minted by the device because only the device knows when it booted.
	// Opaque and compared only for equality, so its length and alphabet are
	// the device's business. Omitted by firmware that predates this, which
	// reads as "cannot say" rather than as a change.
	Boot string `json:"boot,omitempty"`
}

// RenewCode is sent by a device asking for a pairing code when the one it
// was issued has lapsed. Codes live five minutes, and before this the
// only way to another was restarting the listener, which drops every
// live session.
//
// Additive: a server that does not know the type logs it and carries on,
// and a device that never sends it is unaffected. No protocol bump --
// MinProtocolVersion gates the register message, and raising it would
// lock out devices that work.
type RenewCode struct {
	Type string `json:"type"` // "renew_code"
}

// CodeIssued answers a RenewCode.
//
// A distinct type rather than reusing Registered, which also carries a
// code: the device's registration read accepts only registered or error
// and errors on anything else, so a Registered arriving outside that
// window would break an older device. Keeping them separate means this
// reply can only ever follow a request, which is the property that makes
// the change safe in both directions.
type CodeIssued struct {
	Type string `json:"type"`           // "code_issued"
	Code string `json:"code,omitempty"` // empty when the server issues none
}

// Registered is sent by the server after a successful register. Code is
// populated only when the device sent WantCode=true (and pairing is
// enabled server-side); legacy devices that don't set WantCode get a
// bare {"type":"registered"} reply.
type Registered struct {
	Type string `json:"type"`           // "registered"
	Code string `json:"code,omitempty"` // 6-digit pairing code

	// Versions is the newest published release of each BitBang client
	// project, keyed by product ("cli", "octoprint"). Every device gets
	// the same table and looks up its own row, so a client never has to
	// say what it is or what version it runs -- which is the whole point
	// of answering here instead of letting clients poll GitHub.
	//
	// Omitted when the server tracks nothing. A client that finds no key
	// for itself says nothing.
	Versions map[string]string `json:"versions,omitempty"`
}

// Hello is the first thing the server writes on a connector socket --
// /ws/client/<uid> and /ws/pair alike -- before the connector has sent
// anything. It exists to carry Versions to the side of a session that has
// no registration to stamp it on: a device is told about a release in the
// reply to a register it was already making, and a connector has no such
// reply.
//
// Sent unconditionally when the table is non-empty, so it says nothing
// about the connector, the UID it asked for, or whether that device
// exists. Connectors that predate it ignore an unknown type (the CLI logs
// it under -v, bootstrap.js falls through its dispatch), which is what
// makes this safe to deploy ahead of any client.
type Hello struct {
	Type string `json:"type"` // "hello"

	// Versions is the same table Registered carries, with the same
	// contract -- see there.
	Versions map[string]string `json:"versions,omitempty"`
}

// Error is sent by the server when any validation/auth step fails.
//
// Code is what a program matches on; Message is for a person, or a log.
// Message used to be both, half machine tokens and half English sentences,
// and the browser matched on the English -- so rewording "Device not found"
// here would have quietly turned it into "Connection failed" there.
//
// Message is unchanged for every error that predates Code, token or not:
// the CLI and the firmware match on the tokens (unknown_code, preempted,
// protocol_too_old), and an older browser on the English. Build one with
// NewError so the two are always filled in together.
type Error struct {
	Type    string `json:"type"`    // "error"
	Code    string `json:"code"`    // one of the Err* constants
	Message string `json:"message"` // human-readable
}

// Error codes. Snake case, and never reworded: they are the contract.
const (
	ErrUnknownCode      = "unknown_code"       // pairing code not found or expired
	ErrDeviceNotFound   = "device_not_found"   // no device registered under that UID
	ErrPreempted        = "preempted"          // another connection registered this UID
	ErrInvalidUID       = "invalid_uid"        // register: UID is malformed
	ErrExpectedRegister = "expected_register"  // first message was not a register
	ErrProtocolTooOld   = "protocol_too_old"   // register: protocol version unsupported
	ErrMissingPublicKey = "missing_public_key" // register: no public_key
	ErrInvalidPublicKey = "invalid_public_key" // register: public_key does not parse
	ErrUIDKeyMismatch   = "uid_key_mismatch"   // register: UID is not hash(public_key)
	ErrRejectedKey      = "rejected_key"       // register: key type or size not accepted
)

// NewError builds an Error with both fields.
func NewError(code, message string) Error {
	return Error{Type: "error", Code: code, Message: message}
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

	// DeviceBoot is the boot identity from Register, stamped here as well as
	// announced in DeviceUp. Two routes for one fact, and this is the one
	// that cannot go missing: a notification needs a client attached at the
	// moment it is sent, while every session that comes up at all comes up
	// through an offer. So a missed DeviceUp costs latency and the check
	// still happens.
	DeviceBoot string `json:"device_boot,omitempty"`
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

// DeviceUp tells an attached client that a device has registered for its
// UID, and which run of the firmware that is.
//
// Sent on every registration, including the one that replaces a connection
// the server still held. Whether anything should happen about it is the
// browser's to decide by comparing Boot against the one it has been talking
// to: different means the device restarted and the page's state is stale,
// the same means signaling reconnected under a device that never stopped
// running.
//
// There is deliberately no matching "device_down". The server could only
// work out that a device had gone by missing keepalives, which for a device
// halted by a programming tool means waiting out a read deadline -- and it
// would be telling the browser something its own transport is about to
// discover anyway. What the browser cannot work out for itself is whether
// the thing that came back is the thing it was talking to, and that is all
// this says.
type DeviceUp struct {
	Type string `json:"type"` // "device_up"

	// Boot is the registering device's boot identity, or empty from firmware
	// that does not send one -- in which case a browser has nothing to
	// compare and should assume the worst, since a device it cannot identify
	// is one it cannot vouch for the freshness of.
	Boot string `json:"boot,omitempty"`
}

// BuildStamp tells a client which build of the browser runtime this server
// is serving: the same value spliced into bootstrap.js and sw.js as they are
// served.
//
// Sent when a client socket connects and again whenever the value moves. A
// page compares it with the stamp it was loaded with, and a difference means
// the page is running code the server no longer serves -- so it offers a
// reload. Without this an open tab only found out on its next load, or when a
// thirty-minute poll next fetched sw.js.
//
// Connecting counts, not just changing, because of how deploys usually
// happen: the server restarts, every client socket drops, and the browser
// redials. Its first message on the new socket is then the new stamp.
//
// "build_stamp" and not "build" because "build" is already the reply on the
// page/worker postMessage channel, and the same word meaning two things on two
// channels is the confusion the rest of this protocol is trying to get out of.
type BuildStamp struct {
	Type  string `json:"type"` // "build_stamp"
	Build string `json:"build"`
}

// Envelope is used to peek at the "type" field before fully deserializing.
type Envelope struct {
	Type     string `json:"type"`
	ClientID string `json:"client_id,omitempty"`
}
