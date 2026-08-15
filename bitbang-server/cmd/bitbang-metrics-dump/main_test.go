package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bitbang-server-go/internal/metrics"
)

// countStub is a fixed metrics.Counter, enough to construct a Recorder so
// the test builds the snapshots table with the real production schema.
type countStub int

func (c countStub) Count() int { return int(c) }

// newSchemaDB creates a metrics database using the real recorder, so the
// snapshots table matches exactly what the server writes. Tests using it
// fail if the schema drifts.
func newSchemaDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "metrics.db")
	rec, err := metrics.NewRecorder(
		metrics.New(), countStub(0), countStub(0),
		dbPath, time.Minute,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	if rec == nil {
		t.Fatal("NewRecorder returned nil for a non-empty path")
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}
	return dbPath
}

// insertRow writes one snapshot row directly, so the test controls the
// timestamps (and therefore the ordering) deterministically.
func insertRow(t *testing.T, path, ts string, devices, clients, requests int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open for insert: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`
		INSERT INTO snapshots (ts, devices, clients, requests, direct, relay, tcp_relay, failed)
		VALUES (?, ?, ?, ?, 0, 0, 0, 0)
	`, ts, devices, clients, requests)
	if err != nil {
		t.Fatalf("insert row: %v", err)
	}
}

func seededDB(t *testing.T) string {
	path := newSchemaDB(t)
	insertRow(t, path, "2026-07-31T00:00:00Z", 1, 1, 100)
	insertRow(t, path, "2026-07-31T00:05:00Z", 2, 2, 200)
	insertRow(t, path, "2026-07-31T00:10:00Z", 3, 3, 300)
	return path
}

func TestQueryRows_NewestFirst(t *testing.T) {
	db, err := openDB(seededDB(t))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	got, err := queryRows(db, 1)
	if err != nil {
		t.Fatalf("queryRows(1): %v", err)
	}
	if len(got) != 1 || got[0].TS != "2026-07-31T00:10:00Z" || got[0].Requests != 300 {
		t.Fatalf("latest row = %+v, want the 00:10 / requests=300 row", got)
	}

	all, err := queryRows(db, 100)
	if err != nil {
		t.Fatalf("queryRows(100): %v", err)
	}
	wantTS := []string{"2026-07-31T00:10:00Z", "2026-07-31T00:05:00Z", "2026-07-31T00:00:00Z"}
	if len(all) != len(wantTS) {
		t.Fatalf("queryRows(100): want %d rows, got %d", len(wantTS), len(all))
	}
	for i, w := range wantTS {
		if all[i].TS != w {
			t.Errorf("row %d ts = %q, want %q (expected newest-first)", i, all[i].TS, w)
		}
	}
}

func TestQueryRows_EmptyDB(t *testing.T) {
	db, err := openDB(newSchemaDB(t))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	got, err := queryRows(db, 10)
	if err != nil {
		t.Fatalf("queryRows on empty DB: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty DB: want 0 rows, got %d", len(got))
	}
}

func TestOpenDB_MissingFileErrorsAndDoesNotCreate(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.db")
	if _, err := openDB(missing); err == nil {
		t.Fatal("openDB on a missing file should error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("openDB created %s; it must be read-only and side-effect-free (stat err: %v)", missing, err)
	}
}

// TestOpenDB_RejectsWrites proves the read-only guarantee that matters:
// the connection cannot modify recorded metrics. mode=ro blocks writes at
// the VFS layer and query_only blocks them at the SQL layer; either way,
// data-modifying statements fail and the rows are left intact.
func TestOpenDB_RejectsWrites(t *testing.T) {
	db, err := openDB(seededDB(t))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	for _, stmt := range []string{
		`INSERT INTO snapshots (ts,devices,clients,requests,direct,relay,tcp_relay,failed)
			VALUES ('2026-07-31T09:99:99Z',0,0,0,0,0,0,0)`,
		`UPDATE snapshots SET requests = 0`,
		`DELETE FROM snapshots`,
	} {
		if _, err := db.Exec(stmt); err == nil {
			t.Errorf("write succeeded but must be rejected: %s", stmt)
		}
	}

	rows, err := queryRows(db, 100)
	if err != nil {
		t.Fatalf("queryRows: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows after rejected writes = %d, want 3 unchanged", len(rows))
	}
}

// TestOpenDB_SpecialCharPath exercises readonlyDSN: a database whose path
// contains characters that must be percent-encoded in a file: URI (a space
// and a %) still has to open and read back. The writer uses the raw path
// and the reader goes through readonlyDSN, so they must resolve to the same
// file.
func TestOpenDB_SpecialCharPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "od d 50%")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "metrics.db")

	rec, err := metrics.NewRecorder(
		metrics.New(), countStub(0), countStub(0),
		path, time.Minute,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}
	insertRow(t, path, "2026-07-31T00:00:00Z", 1, 2, 42)

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("openDB on a path with a space and %%: %v", err)
	}
	defer db.Close()

	got, err := queryRows(db, 1)
	if err != nil {
		t.Fatalf("queryRows: %v", err)
	}
	if len(got) != 1 || got[0].Requests != 42 {
		t.Fatalf("read back = %+v, want requests=42", got)
	}
}

// TestOpenDB_RelativePath guards against the file: URI treating a relative
// path as an authority (file://name). openDB must resolve it to an absolute
// path first. This is how the tool is used with `-db metrics.db` or
// METRICS_PATH=metrics.db.
func TestOpenDB_RelativePath(t *testing.T) {
	path := seededDB(t)
	t.Chdir(filepath.Dir(path))

	db, err := openDB(filepath.Base(path))
	if err != nil {
		t.Fatalf("openDB(relative): %v", err)
	}
	defer db.Close()

	got, err := queryRows(db, 1)
	if err != nil {
		t.Fatalf("queryRows: %v", err)
	}
	if len(got) != 1 || got[0].Requests != 300 {
		t.Fatalf("relative-path read = %+v, want requests=300", got)
	}
}

func TestRun_LatestObject(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"-db", seededDB(t)}, &out, &errb); err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errb.String())
	}
	var got row
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\n%s", err, out.String())
	}
	if got.TS != "2026-07-31T00:10:00Z" || got.Requests != 300 {
		t.Fatalf("latest object = %+v, want the 00:10 / requests=300 row", got)
	}
}

func TestRun_HistoryArray(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"-db", seededDB(t), "-history", "5"}, &out, &errb); err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errb.String())
	}
	var got []row
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, out.String())
	}
	if len(got) != 3 || got[0].TS != "2026-07-31T00:10:00Z" {
		t.Fatalf("history array = %+v, want 3 rows newest-first", got)
	}
}

func TestRun_EmptyDB_EmitsNull(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"-db", newSchemaDB(t)}, &out, &errb); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out.String()) != "null" {
		t.Fatalf("empty DB stdout = %q, want null", out.String())
	}
	if !strings.Contains(errb.String(), "no snapshots") {
		t.Fatalf("empty DB stderr = %q, want a 'no snapshots' note", errb.String())
	}
}

func TestRun_EmptyHistory_EmitsArray(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"-db", newSchemaDB(t), "-history", "5"}, &out, &errb); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("empty history stdout = %q, want []", out.String())
	}
}

func TestRun_EnvFallback(t *testing.T) {
	t.Setenv("METRICS_PATH", seededDB(t))
	var out, errb bytes.Buffer
	if err := run(nil, &out, &errb); err != nil {
		t.Fatalf("run with $METRICS_PATH: %v (stderr: %s)", err, errb.String())
	}
	var got row
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not a JSON object: %v\n%s", err, out.String())
	}
	if got.Requests != 300 {
		t.Fatalf("env-fallback latest = %+v, want requests=300", got)
	}
}

func TestRun_NoPath_Errors(t *testing.T) {
	t.Setenv("METRICS_PATH", "")
	var out, errb bytes.Buffer
	err := run(nil, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "no database path") {
		t.Fatalf("run with no path: err = %v, want a 'no database path' error", err)
	}
}

func TestRun_NegativeHistory_Errors(t *testing.T) {
	var out, errb bytes.Buffer
	err := run([]string{"-db", seededDB(t), "-history", "-1"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), ">= 0") {
		t.Fatalf("negative history: err = %v, want a '>= 0' error", err)
	}
}

// TestRowJSONKeys pins the output contract: the counter keys inherited from
// the embedded metrics.Snapshot, plus ts and the two gauges. These counter
// keys are the ones /status also emits; the full /status object carries more
// (version, protocol, active_codes), so this is a subset, not the same set.
func TestRowJSONKeys(t *testing.T) {
	r := row{TS: "2026-07-31T00:00:00Z", Devices: 4, Clients: 7}
	r.Requests = 11
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)
	for _, key := range []string{
		`"ts"`, `"devices"`, `"clients"`,
		`"connection_requests_total"`,
		`"connections_direct_total"`,
		`"connections_relay_total"`,
		`"connections_tcp_relay_total"`,
		`"connections_failed_total"`,
	} {
		if !strings.Contains(out, key) {
			t.Errorf("row JSON missing key %s; got %s", key, out)
		}
	}
}
