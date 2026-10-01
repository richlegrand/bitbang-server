package handler

import (
	"testing"

	"bitbang-server-go/internal/wire"
)

// Every error the server sends carries a code to match on, and keeps the
// message it had before codes existed: the CLI, the firmware and older
// browsers still match on those.
func TestErrorsCarryCodeAndKeepMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: the unknown-device path sleeps 3s by design")
	}

	t.Run("device not found", func(t *testing.T) {
		srv, _, teardown := testServer(t)
		defer teardown()
		uid, _ := newTestIdentity(t)
		c := dialWS(t, srv, "/ws/client/"+uid)
		defer c.Close()
		checkError(t, readMsg(t, c, "error"), wire.ErrDeviceNotFound, "Device not found")
	})

	t.Run("protocol too old", func(t *testing.T) {
		srv, _, teardown := testServer(t)
		defer teardown()
		uid, pub := newTestIdentity(t)
		dev := dialWS(t, srv, "/ws/device/"+uid)
		defer dev.Close()
		writeJSON(t, dev, map[string]any{"type": "register", "protocol": 1, "public_key": pub})
		checkError(t, readMsg(t, dev, "error"), wire.ErrProtocolTooOld, "protocol_too_old")
	})

	t.Run("uid does not match key", func(t *testing.T) {
		srv, _, teardown := testServer(t)
		defer teardown()
		uid, _ := newTestIdentity(t)
		_, otherPub := newTestIdentity(t)
		dev := dialWS(t, srv, "/ws/device/"+uid)
		defer dev.Close()
		writeJSON(t, dev, map[string]any{"type": "register", "protocol": 3, "public_key": otherPub})
		checkError(t, readMsg(t, dev, "error"), wire.ErrUIDKeyMismatch, "UID does not match public key")
	})

	t.Run("preempted", func(t *testing.T) {
		srv, _, teardown := testServer(t)
		defer teardown()
		uid, pub := newTestIdentity(t)
		first := dialWS(t, srv, "/ws/device/"+uid)
		defer first.Close()
		writeJSON(t, first, map[string]any{"type": "register", "protocol": 3, "public_key": pub})
		readMsg(t, first, "registered")
		second := dialWS(t, srv, "/ws/device/"+uid)
		defer second.Close()
		writeJSON(t, second, map[string]any{"type": "register", "protocol": 3, "public_key": pub})
		checkError(t, readMsg(t, first, "error"), wire.ErrPreempted, "preempted")
	})
}

func checkError(t *testing.T, msg map[string]any, code, message string) {
	t.Helper()
	if msg["code"] != code {
		t.Errorf("code = %v, want %q", msg["code"], code)
	}
	if msg["message"] != message {
		t.Errorf("message = %v, want %q -- clients match on it", msg["message"], message)
	}
}
