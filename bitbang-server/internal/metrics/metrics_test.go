package metrics

import (
	"sync"
	"testing"
)

func TestIncPath_KnownValues(t *testing.T) {
	m := New()
	m.IncPath("direct")
	m.IncPath("direct")
	m.IncPath("relay")
	m.IncPath("tcp-relay")
	m.IncPath("failed")

	snap := m.Snapshot()
	if snap.Direct != 2 {
		t.Errorf("Direct = %d, want 2", snap.Direct)
	}
	if snap.Relay != 1 {
		t.Errorf("Relay = %d, want 1", snap.Relay)
	}
	if snap.TCPRelay != 1 {
		t.Errorf("TCPRelay = %d, want 1", snap.TCPRelay)
	}
	if snap.Failed != 1 {
		t.Errorf("Failed = %d, want 1", snap.Failed)
	}
}

func TestIncPath_UnknownValue(t *testing.T) {
	m := New()
	// A future path value the server doesn't know — should not panic,
	// should not increment any of the known counters.
	m.IncPath("quantum-entangled")
	m.IncPath("")

	snap := m.Snapshot()
	if snap.Direct != 0 || snap.Relay != 0 || snap.TCPRelay != 0 || snap.Failed != 0 {
		t.Errorf("unknown path bumped a known counter: %+v", snap)
	}
}

func TestIncRequests(t *testing.T) {
	m := New()
	for i := 0; i < 5; i++ {
		m.IncRequests()
	}
	if got := m.Snapshot().Requests; got != 5 {
		t.Errorf("Requests = %d, want 5", got)
	}
}

// TestConcurrent verifies that the atomic counters survive concurrent
// writers without losing increments — this is the property atomic.Int64
// gives us, but a smoke test catches a regression to non-atomic access
// (e.g., someone refactoring to plain int64).
func TestConcurrent(t *testing.T) {
	m := New()
	const writers = 16
	const perWriter = 1000

	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				m.IncRequests()
				m.IncPath("direct")
			}
		}()
	}
	wg.Wait()

	snap := m.Snapshot()
	want := int64(writers * perWriter)
	if snap.Requests != want {
		t.Errorf("Requests = %d, want %d (lost increments under concurrency)", snap.Requests, want)
	}
	if snap.Direct != want {
		t.Errorf("Direct = %d, want %d (lost increments under concurrency)", snap.Direct, want)
	}
}
