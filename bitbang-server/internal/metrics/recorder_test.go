package metrics

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

// fakeCounter is a tiny in-test implementation of the Counter interface so
// we don't need to spin up real registries to drive the recorder.
type fakeCounter struct{ n int }

func (f *fakeCounter) Count() int { return f.n }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// TestNewRecorder_EmptyPath verifies that an empty path returns nil
// without error — this is how main.go disables the recorder when
// METRICS_PATH is unset.
func TestNewRecorder_EmptyPath(t *testing.T) {
	r, err := NewRecorder(New(), &fakeCounter{}, &fakeCounter{}, "", time.Second, discardLogger())
	if err != nil {
		t.Errorf("empty path returned err: %v", err)
	}
	if r != nil {
		t.Errorf("empty path returned non-nil recorder: %+v", r)
	}
}

// TestNewRecorder_CreatesSchema verifies that opening with a fresh path
// creates the file, applies PRAGMAs, and creates the schema.
func TestNewRecorder_CreatesSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	r, err := NewRecorder(New(), &fakeCounter{}, &fakeCounter{}, path, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer r.Close()

	// Confirm the schema exists by querying it directly.
	var count int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM snapshots").Scan(&count); err != nil {
		t.Errorf("snapshots table missing: %v", err)
	}
	if count != 0 {
		t.Errorf("fresh DB should have 0 rows, got %d", count)
	}
}

// TestWriteSnapshot_RoundTrip writes a snapshot, reads it back via
// LoadLastSnapshot, verifies the counter values match.
func TestWriteSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	m := New()
	m.IncRequests()
	m.IncRequests()
	m.IncPath("direct")
	m.IncPath("relay")
	m.IncPath("failed")

	devices := &fakeCounter{n: 7}
	clients := &fakeCounter{n: 3}

	r, err := NewRecorder(m, devices, clients, path, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer r.Close()

	if err := r.WriteSnapshot(); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	got, err := r.LoadLastSnapshot()
	if err != nil {
		t.Fatalf("LoadLastSnapshot: %v", err)
	}
	if got.Requests != 2 || got.Direct != 1 || got.Relay != 1 || got.Failed != 1 {
		t.Errorf("round-trip wrong: %+v", got)
	}
}

// TestLoadLastSnapshot_NoRows verifies that an empty DB returns a zero
// Snapshot with no error — used by main.go to seed metrics safely on a
// fresh deploy.
func TestLoadLastSnapshot_NoRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	r, err := NewRecorder(New(), &fakeCounter{}, &fakeCounter{}, path, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer r.Close()

	got, err := r.LoadLastSnapshot()
	if err != nil {
		t.Errorf("expected nil error on empty DB, got: %v", err)
	}
	if (got != Snapshot{}) {
		t.Errorf("expected zero Snapshot on empty DB, got %+v", got)
	}
}

// TestRun_AppendsMultipleRows verifies that Run writes snapshots over
// multiple ticks and that counter values across rows reflect intermediate
// state changes (the same property we tested for JSONL).
func TestRun_AppendsMultipleRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	m := New()
	m.IncRequests()

	devices := &fakeCounter{n: 1}
	clients := &fakeCounter{n: 0}

	r, err := NewRecorder(m, devices, clients, path, 20*time.Millisecond, discardLogger())
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	time.Sleep(120 * time.Millisecond)
	m.IncRequests()
	time.Sleep(60 * time.Millisecond)

	cancel()
	<-done

	rows, err := r.db.Query("SELECT ts, requests FROM snapshots ORDER BY ts ASC")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	type rec struct {
		ts       string
		requests int64
	}
	var got []rec
	for rows.Next() {
		var rr rec
		if err := rows.Scan(&rr.ts, &rr.requests); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, rr)
	}
	if len(got) < 3 {
		t.Fatalf("want at least 3 snapshot rows, got %d: %+v", len(got), got)
	}
	// Sanity: rows should be monotonically non-decreasing in requests
	// (we never decrement, never restart).
	for i := 1; i < len(got); i++ {
		if got[i].requests < got[i-1].requests {
			t.Errorf("requests decreased between rows %d (%d) and %d (%d) — should be monotonic",
				i-1, got[i-1].requests, i, got[i].requests)
		}
	}
}

// TestResume_FullCycle is the integration test for the headline feature:
// write some snapshots, close, reopen, load, verify counters resume.
func TestResume_FullCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	// Pass 1: record some state and close.
	{
		m := New()
		m.IncRequests()
		m.IncRequests()
		m.IncRequests()
		m.IncPath("direct")
		m.IncPath("direct")
		m.IncPath("relay")

		r, err := NewRecorder(m, &fakeCounter{n: 4}, &fakeCounter{n: 2}, path, time.Second, discardLogger())
		if err != nil {
			t.Fatalf("NewRecorder: %v", err)
		}
		if err := r.WriteSnapshot(); err != nil {
			t.Fatalf("WriteSnapshot: %v", err)
		}
		_ = r.Close()
	}

	// Pass 2: fresh process — open the same DB, load the snapshot, seed
	// new Metrics, verify they continue from the persisted values.
	{
		m := New()
		r, err := NewRecorder(m, &fakeCounter{n: 4}, &fakeCounter{n: 2}, path, time.Second, discardLogger())
		if err != nil {
			t.Fatalf("NewRecorder pass 2: %v", err)
		}
		defer r.Close()

		snap, err := r.LoadLastSnapshot()
		if err != nil {
			t.Fatalf("LoadLastSnapshot: %v", err)
		}
		m.Load(snap)

		got := m.Snapshot()
		if got.Requests != 3 || got.Direct != 2 || got.Relay != 1 {
			t.Errorf("counters did not resume correctly: %+v", got)
		}

		// Increment after resume — counts should continue, not restart.
		m.IncRequests()
		m.IncPath("direct")
		if err := r.WriteSnapshot(); err != nil {
			t.Fatalf("WriteSnapshot post-resume: %v", err)
		}

		latest, err := r.LoadLastSnapshot()
		if err != nil {
			t.Fatalf("LoadLastSnapshot post-resume: %v", err)
		}
		if latest.Requests != 4 || latest.Direct != 3 {
			t.Errorf("post-resume increment didn't continue from seeded values: %+v", latest)
		}
	}
}

// TestRun_RespectsContextCancel verifies that Run returns promptly when
// ctx is cancelled — important for clean shutdown.
func TestRun_RespectsContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")

	r, err := NewRecorder(New(), &fakeCounter{}, &fakeCounter{}, path, time.Hour, discardLogger())
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// expected — ctx cancel exits the loop
	case <-time.After(200 * time.Millisecond):
		t.Errorf("Run did not return promptly after ctx cancel")
	}
}

// silenceLint keeps database/sql imported (used implicitly via the
// recorder's internal db handle, but also referenced explicitly below).
var _ = sql.ErrNoRows
