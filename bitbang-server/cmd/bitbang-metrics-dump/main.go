// Command bitbang-metrics-dump reads the metrics SQLite database written
// by the signaling server's recorder (internal/metrics) and prints
// snapshot rows as JSON.
//
// Usage:
//
//	bitbang-metrics-dump -db PATH              # latest snapshot, as a JSON object
//	bitbang-metrics-dump -db PATH -history 100 # last 100 snapshots, as a JSON array
//
// -db defaults to $METRICS_PATH. The deploy ships this binary to
// /opt/bitbang and sets METRICS_PATH only in the systemd unit, not in an
// interactive shell, so on the server the invocation is explicit:
//
//	/opt/bitbang/bitbang-metrics-dump -db /opt/bitbang/metrics.db | jq .
//
// Rows are ordered newest-first. The counter keys are the wire-stable
// names /status emits, because the row type embeds metrics.Snapshot.
//
// The tool is read-only: it opens the database with a mode=ro URI and
// PRAGMA query_only, so it never creates the database and never modifies a
// recorded row. It is safe to run against a live server's database.
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"bitbang-server-go/internal/metrics"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers as "sqlite"
)

// row is one snapshot row. The counter fields come from the embedded
// metrics.Snapshot, so their JSON tags stay in step with /status. ts and
// the two gauges are the extra columns the recorder writes; see the schema
// in internal/metrics/recorder.go.
type row struct {
	TS      string `json:"ts"`
	Devices int64  `json:"devices"`
	Clients int64  `json:"clients"`
	metrics.Snapshot
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // flag already printed usage to stderr
		}
		fmt.Fprintln(os.Stderr, "bitbang-metrics-dump:", err)
		os.Exit(1)
	}
}

// run takes its args and output streams explicitly instead of reading
// os.Args / os.Stdout, so the command can be driven from tests.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("bitbang-metrics-dump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", os.Getenv("METRICS_PATH"),
		"path to the metrics SQLite database (default $METRICS_PATH)")
	history := fs.Int("history", 0,
		"print the last N snapshots as a JSON array; 0 prints just the latest, as an object")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dbPath == "" {
		return fmt.Errorf("no database path: pass -db or set METRICS_PATH")
	}
	if *history < 0 {
		return fmt.Errorf("-history must be >= 0, got %d", *history)
	}

	db, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")

	if *history > 0 {
		rows, err := queryRows(db, *history)
		if err != nil {
			return err
		}
		if rows == nil {
			rows = []row{} // encode [] rather than null for the array form
		}
		return enc.Encode(rows)
	}

	rows, err := queryRows(db, 1)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		// No snapshots recorded yet. Emit JSON null so a downstream
		// `| jq .` still gets valid input, and note it on stderr.
		fmt.Fprintf(stderr, "bitbang-metrics-dump: no snapshots in %s\n", *dbPath)
		return enc.Encode(nil)
	}
	return enc.Encode(rows[0])
}

// openDB opens the metrics database read-only: mode=ro so the driver never
// creates it (os.Stat first for a friendlier "not found"), plus PRAGMA
// query_only to reject writes at the SQL layer.
func openDB(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// Resolve to an absolute path so the file: URI has an empty authority
	// (file:///path); a relative path would be parsed as a URI host.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", readonlyDSN(abs))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA query_only = true"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open %s: set query_only: %w", path, err)
	}
	return db, nil
}

// readonlyDSN builds a read-only SQLite file: URI (mode=ro). path must be
// absolute, so the URI has an empty authority (file:///path); url.URL
// percent-encodes it so spaces or other reserved characters resolve to the
// literal filename.
func readonlyDSN(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}).String()
}

// queryRows returns up to limit snapshot rows, newest first.
func queryRows(db *sql.DB, limit int) ([]row, error) {
	q, err := db.Query(`
		SELECT ts, devices, clients, requests, direct, relay, tcp_relay, failed
		FROM snapshots
		ORDER BY ts DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer q.Close()

	var out []row
	for q.Next() {
		var r row
		if err := q.Scan(
			&r.TS, &r.Devices, &r.Clients,
			&r.Requests, &r.Direct, &r.Relay, &r.TCPRelay, &r.Failed,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		out = append(out, r)
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return out, nil
}
