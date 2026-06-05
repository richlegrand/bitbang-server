package handler

import "testing"

// TestPairInflight_PerIPSerializes verifies the per-IP semaphore
// behavior in isolation: one IP can hold at most one slot at a time.
// Different IPs are independent.
func TestPairInflight_PerIPSerializes(t *testing.T) {
	// Clear global state in case earlier tests touched it.
	pairInflightMu.Lock()
	for k := range pairInflight {
		delete(pairInflight, k)
	}
	pairInflightMu.Unlock()

	if !acquirePairSlot("1.2.3.4") {
		t.Fatal("first acquire for 1.2.3.4 should succeed")
	}
	if acquirePairSlot("1.2.3.4") {
		t.Error("second concurrent acquire for 1.2.3.4 should fail")
	}
	if !acquirePairSlot("5.6.7.8") {
		t.Error("acquire for different IP should succeed in parallel")
	}

	releasePairSlot("1.2.3.4")
	if !acquirePairSlot("1.2.3.4") {
		t.Error("acquire after release should succeed")
	}

	releasePairSlot("1.2.3.4")
	releasePairSlot("5.6.7.8")

	// After both release, the map should be empty.
	pairInflightMu.Lock()
	got := len(pairInflight)
	pairInflightMu.Unlock()
	if got != 0 {
		t.Errorf("after all releases, pairInflight has %d entries, want 0", got)
	}
}

func TestPairInflight_OverReleaseSafe(t *testing.T) {
	// Defensive: extra releases shouldn't underflow or panic.
	pairInflightMu.Lock()
	for k := range pairInflight {
		delete(pairInflight, k)
	}
	pairInflightMu.Unlock()

	releasePairSlot("9.9.9.9")
	releasePairSlot("9.9.9.9")
	if _, ok := pairInflight["9.9.9.9"]; ok {
		t.Errorf("release-on-empty left a stale entry")
	}
}
