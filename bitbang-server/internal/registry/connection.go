// Package registry holds the live device and client WebSocket connections
// and routes messages between them. The DeviceRegistry interface is the
// single seam that will accept a Redis-backed implementation in the future
// to support horizontal scale; today it's an in-memory sync.Map.
package registry

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/wire"
)

// DeviceConn wraps a device WebSocket with the per-connection state the
// server needs to relay messages and preempt stale connections cleanly.
//
// Writes are serialized through writeMu — gorilla/websocket forbids
// concurrent writes on the same connection.
type DeviceConn struct {
	UID        string
	WS         *websocket.Conn
	ICEServers []wire.ICEServer // device-supplied override; empty if none
	ConnectAt  time.Time

	// PublicKey is the base64 DER SubjectPublicKeyInfo the device presented at
	// register time, retained so clients can fetch it via "request_pubkey".
	// hash(decoded) == UID is enforced before this is stored.
	PublicKey string

	writeMu sync.Mutex
	closed  bool
	closeMu sync.Mutex
}

// SendJSON serializes msg and writes it as a text frame. Safe for concurrent
// callers; the underlying WS write is serialized by writeMu.
func (c *DeviceConn) SendJSON(msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("connection closed")
	}
	return c.WS.WriteMessage(websocket.TextMessage, data)
}

// Close closes the underlying WS exactly once (idempotent). Subsequent
// SendJSON calls will return an error.
func (c *DeviceConn) Close(code int, reason string) {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	// Best-effort close frame, then hard close.
	_ = c.WS.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(time.Second),
	)
	_ = c.WS.Close()
}

// ClientConn wraps a client WebSocket. ClientID is "<deviceUID>_<short-uuid>"
// — the device-UID prefix lets us identify which clients to boot when a
// device gets preempted.
type ClientConn struct {
	ClientID  string // <deviceUID>_<short>
	TargetUID string // the device this client is connected to
	WS        *websocket.Conn
	ConnectAt time.Time

	// BrowserIP is the connecting browser's IP, captured at WS-upgrade time
	// and stamped on relayed "request" messages so devices can attribute
	// bad-code attempts to a source IP. Empty if not yet determined.
	BrowserIP string

	// ForceRelay reflects the ?relay query flag from the browser, captured
	// when the client sent its "request" message. When true, the server
	// includes TURN credentials in the offer at relay time (no withholding);
	// when false, TURN is withheld until the browser explicitly asks via
	// RequestICE.
	ForceRelay bool

	writeMu sync.Mutex
	closed  bool
	closeMu sync.Mutex
}

func (c *ClientConn) SendJSON(msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("connection closed")
	}
	return c.WS.WriteMessage(websocket.TextMessage, data)
}

func (c *ClientConn) Close(code int, reason string) {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	_ = c.WS.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(time.Second),
	)
	_ = c.WS.Close()
}
