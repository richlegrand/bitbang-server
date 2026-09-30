package handler

import (
	"testing"
)

// A client attached to a device is told when a device registers for its UID,
// and told which run of the firmware it is.
//
// The identity is the whole point. A new device connection does not mean a
// restart -- a dropped wss or this server redeploying makes one with the
// firmware still running -- and the browser is holding state that only a
// restart invalidates. So the server forwards what the device said and the
// browser compares; nothing here interprets it.
func TestAClientIsToldWhichBootRegistered(t *testing.T) {
	srv, _, teardown := testServer(t)
	defer teardown()

	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	if err := dev.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "aaaa1111",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev, "registered")

	// No hello to read: the server sends one only when it is tracking
	// releases, and this harness tracks none.
	cli := dialWS(t, srv, "/ws/client/"+uid)
	defer cli.Close()

	// The device goes -- a halt, which is what a flash looks like from here,
	// with nothing said by anyone.
	_ = dev.Close()

	// And comes back as a different run.
	dev2 := dialWS(t, srv, "/ws/device/"+uid)
	defer dev2.Close()
	if err := dev2.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "bbbb2222",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev2, "registered")

	up := readMsg(t, cli, "device_up")
	if up["boot"] != "bbbb2222" {
		t.Errorf("boot = %v, want bbbb2222", up["boot"])
	}
}

// The client keeps its socket while the device is away, which is what the
// announcement needs in order to reach anybody.
//
// This used to answer "Device not found" and close on the first thing the
// client sent -- taking away the channel the return would have been announced
// on, at the one moment it was about to matter.
func TestAnAttachedClientSurvivesTheDeviceLeaving(t *testing.T) {
	srv, _, teardown := testServer(t)
	defer teardown()

	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	if err := dev.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "aaaa1111",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev, "registered")

	cli := dialWS(t, srv, "/ws/client/"+uid)
	defer cli.Close()
	_ = dev.Close()

	// Something already in flight, arriving after the device has gone. It
	// cannot be forwarded and it is not an error either: dropped, socket kept.
	if err := cli.WriteJSON(map[string]any{
		"type": "candidate", "candidate": map[string]any{"candidate": "x"},
	}); err != nil {
		t.Fatal(err)
	}

	dev2 := dialWS(t, srv, "/ws/device/"+uid)
	defer dev2.Close()
	if err := dev2.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "bbbb2222",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev2, "registered")

	// Still here, and told. A closed socket fails this read.
	readMsg(t, cli, "device_up")
}

// A device whose signaling reconnects without restarting reports the same
// identity, which is how a browser knows to keep what it has.
//
// The case the old code could not see. It booted every client on any
// re-registration, so a dropped wss or a server redeploy threw away sessions
// that were working and asked people to reload for nothing.
func TestTheSameBootIsReportedUnchanged(t *testing.T) {
	srv, _, teardown := testServer(t)
	defer teardown()

	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	if err := dev.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "aaaa1111",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev, "registered")

	cli := dialWS(t, srv, "/ws/client/"+uid)
	defer cli.Close()

	// The same firmware, a second connection -- and it is not booted.
	dev2 := dialWS(t, srv, "/ws/device/"+uid)
	defer dev2.Close()
	if err := dev2.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "aaaa1111",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev2, "registered")

	up := readMsg(t, cli, "device_up")
	if up["boot"] != "aaaa1111" {
		t.Errorf("boot = %v, want the unchanged aaaa1111", up["boot"])
	}
}

// Every offer carries the boot identity too.
//
// The route that cannot go missing. device_up needs a client attached at the
// moment it is sent, and the browser's reconnect loop closes and redials its
// socket between attempts, so there are windows where nothing would hear it.
// An offer has no such window: every session that comes up at all comes up
// through one. So a missed announcement costs latency and the check still
// happens.
func TestAnOfferCarriesTheBootIdentity(t *testing.T) {
	srv, _, teardown := testServer(t)
	defer teardown()

	uid, pub := newTestIdentity(t)
	dev := dialWS(t, srv, "/ws/device/"+uid)
	defer dev.Close()
	if err := dev.WriteJSON(map[string]any{
		"type": "register", "protocol": 3, "public_key": pub, "boot": "cccc3333",
	}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, dev, "registered")

	cli := dialWS(t, srv, "/ws/client/"+uid)
	defer cli.Close()
	if err := cli.WriteJSON(map[string]any{"type": "request"}); err != nil {
		t.Fatal(err)
	}

	req := readMsg(t, dev, "request")
	clientID, _ := req["client_id"].(string)
	if clientID == "" {
		t.Fatal("device saw a request with no client_id")
	}
	if err := dev.WriteJSON(map[string]any{
		"type": "offer", "sdp": "v=0", "client_id": clientID,
	}); err != nil {
		t.Fatal(err)
	}

	offer := readMsg(t, cli, "offer")
	if offer["device_boot"] != "cccc3333" {
		t.Errorf("device_boot = %v, want cccc3333", offer["device_boot"])
	}
}
