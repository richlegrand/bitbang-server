package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers as "sqlite"
)

// Counter is the minimum interface a "thing we want to snapshot" implements.
// Just enough so Recorder can read the live gauges (devices, clients) from
// the registry without taking a hard dependency on the registry types.
type Counter interface {
	Count() int
}

// Recorder periodically writes a snapshot row to a SQLite database. One
// goroutine per process; the writer holds the DB connection open and
// INSERTs a row per tick. The DB file is the durable store of the
// monotonic counters — on process restart, main.go calls
// LoadLastSnapshot before serving traffic and seeds the in-memory
// counters via Metrics.Load, so the counters reflect lifetime totals
// modulo at most one snapshot interval's worth of unflushed events.
//
// Schema is created idempotently on Open via CREATE TABLE IF NOT EXISTS;
// no migrations, no separate setup step. The file is opened with
// journal_mode=WAL and synchronous=NORMAL — the standard SQLite recipe
// for "durable enough for the common case, fast enough to never be a
// concern." Per SQLite's own docs, this combination survives any
// process crash and any power loss short of hardware corruption, losing
// at most the most-recent transaction on hard failure.
//
// Storage budget at the default 5-minute interval: ~30 MB/year. WAL
// auto-checkpoints; no manual VACUUM needed for normal operation.
//
// Snapshot row shape (one row per tick, ts is the primary key):
//
//	ts        TEXT (RFC3339 UTC) — primary key, sortable
//	devices   INTEGER (current registered device count, gauge)
//	clients   INTEGER (current connected client count, gauge)
//	requests  INTEGER (cumulative "request" count, monotonic)
//	direct    INTEGER (cumulative direct connect_path reports, monotonic)
//	relay     INTEGER (cumulative relay reports, monotonic)
//	tcp_relay INTEGER (cumulative tcp-relay reports, monotonic)
//	failed    INTEGER (cumulative failed reports, monotonic)
type Recorder struct {
	metrics  *Metrics
	devices  Counter
	clients  Counter
	path     string
	interval time.Duration
	log      *slog.Logger

	db *sql.DB

	// now is injectable so tests can pin timestamps. nil means time.Now.
	now func() time.Time
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS snapshots (
	ts        TEXT NOT NULL PRIMARY KEY,
	devices   INTEGER NOT NULL,
	clients   INTEGER NOT NULL,
	requests  INTEGER NOT NULL,
	direct    INTEGER NOT NULL,
	relay     INTEGER NOT NULL,
	tcp_relay INTEGER NOT NULL,
	failed    INTEGER NOT NULL
);
`

// NewRecorder constructs a Recorder. Returns nil if path is empty (which
// is how main.go disables the recorder when METRICS_PATH is unset). On
// any other error (open failure, schema creation failure) Returns the
// error so main.go can decide whether to refuse to start.
func NewRecorder(m *Metrics, devices, clients Counter, path string, interval time.Duration, log *slog.Logger) (*Recorder, error) {
	if path == "" {
		return nil, nil
	}
	if interval <= 0 {
		return nil, fmt.Errorf("metrics: non-positive interval %v", interval)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("metrics: open %s: %w", path, err)
	}

	// Connection pool tuning: one connection is plenty for our write rate
	// (one INSERT per interval) and SQLite-with-WAL handles single
	// concurrent writer + many concurrent readers cleanly. We never need
	// more than one writer.
	db.SetMaxOpenConns(1)

	// PRAGMAs: WAL for crash safety + reader-writer concurrency,
	// synchronous=NORMAL for the standard durability/speed tradeoff
	// (recommended by SQLite for non-financial-grade applications).
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("metrics: %s: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("metrics: schema: %w", err)
	}

	return &Recorder{
		metrics:  m,
		devices:  devices,
		clients:  clients,
		path:     path,
		interval: interval,
		log:      log,
		db:       db,
	}, nil
}

// Close releases the database handle. Safe to call multiple times.
func (r *Recorder) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	err := r.db.Close()
	r.db = nil
	return err
}

// LoadLastSnapshot returns the most-recent persisted snapshot's counter
// values, or a zero Snapshot if no rows exist. Used at startup by
// main.go to seed the in-memory counters via Metrics.Load.
//
// Returns an error only on actual database failures (file unreadable,
// schema mismatch). A missing row — fresh deploy, brand new DB file —
// is not an error; the returned Snapshot is the natural zero value.
func (r *Recorder) LoadLastSnapshot() (Snapshot, error) {
	if r == nil || r.db == nil {
		return Snapshot{}, nil
	}
	var s Snapshot
	err := r.db.QueryRow(`
		SELECT requests, direct, relay, tcp_relay, failed
		FROM snapshots
		ORDER BY ts DESC
		LIMIT 1
	`).Scan(&s.Requests, &s.Direct, &s.Relay, &s.TCPRelay, &s.Failed)
	if err == sql.ErrNoRows {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("metrics: load last: %w", err)
	}
	return s, nil
}

// Run drives the periodic snapshot loop until ctx is cancelled. Write
// errors are logged at warn level and the loop continues — a disk
// hiccup shouldn't take the signaling process down.
func (r *Recorder) Run(ctx context.Context) {
	if r == nil {
		return
	}
	tick := time.NewTicker(r.interval)
	defer tick.Stop()

	r.log.Info("metrics recorder started", "path", r.path, "interval", r.interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := r.WriteSnapshot(); err != nil {
				r.log.Warn("metrics recorder: write failed", "path", r.path, "err", err)
			}
		}
	}
}

// WriteSnapshot inserts one row for the current counter state. Exported
// so main.go can call it once at startup (after Load) to make the
// first post-restart row reflect the seeded state, before the periodic
// ticker takes over.
func (r *Recorder) WriteSnapshot() error {
	if r == nil || r.db == nil {
		return nil
	}
	nowFn := r.now
	if nowFn == nil {
		nowFn = time.Now
	}
	snap := r.metrics.Snapshot()
	_, err := r.db.Exec(`
		INSERT INTO snapshots (ts, devices, clients, requests, direct, relay, tcp_relay, failed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		nowFn().UTC().Format(time.RFC3339Nano),
		r.devices.Count(),
		r.clients.Count(),
		snap.Requests,
		snap.Direct,
		snap.Relay,
		snap.TCPRelay,
		snap.Failed,
	)
	if err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}
	return nil
}
