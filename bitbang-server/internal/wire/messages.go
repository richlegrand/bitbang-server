// Package wire defines the JSON message types exchanged between the
// signaling server and devices/clients over WebSocket.
//
// All messages are JSON objects with a "type" string discriminator.
// Unknown fields are tolerated on inbound messages (forward compatibility);
// outbound messages set only the fields the protocol requires.
package wire

// Protocol versioning. Devices send their supported version in the register
// message; the server rejects anything below MinProtocolVersion.
const (
	ProtocolVersion    = 2
	MinProtocolVersion = 2
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
type Register struct {
	Type       string      `json:"type"` // "register"
	Protocol   int         `json:"protocol"`
	PublicKey  string      `json:"public_key"`
	ICEServers []ICEServer `json:"ice_servers,omitempty"` // device-supplied override
}

// Registered is sent by the server after a successful register.
type Registered struct {
	Type string `json:"type"` // "registered"
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
// The server augments it with client_id and ice_servers before forwarding.
type Request struct {
	Type       string      `json:"type"` // "request"
	ClientID   string      `json:"client_id,omitempty"`
	ICEServers []ICEServer `json:"ice_servers,omitempty"`
}

// Envelope is used to peek at the "type" field before fully deserializing.
type Envelope struct {
	Type     string `json:"type"`
	ClientID string `json:"client_id,omitempty"`
}
