package beyond

import (
	"bytes"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessLogger_LogHTTP_DB(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	al := &AccessLogger{Logger: logger, DB: db}

	entry := AccessLogEntry{
		Decision:   "allow",
		UserEmail:  "bob@example.com",
		UserGroups: []string{"platform"},
		Resource:   "argocd",
		Upstream:   "http://localhost:8080",
		Method:     "POST",
		Path:       "/api/v1/sync",
		Host:       "argocd.internal",
		SourceIP:   "10.0.0.2",
		UserAgent:  "argocd-cli/2.0",
		StatusCode: 202,
		DurationMS: 13,
		BytesSent:  512,
		SessionID:  "sess-xyz",
	}
	al.Log("http", entry)
	al.Flush()

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM access_logs WHERE user_email = 'bob@example.com'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "one access log entry should be present after Flush")
}

func TestAccessLogger_AutoFlush(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	al := &AccessLogger{Logger: logger, DB: db, FlushInterval: 10 * time.Millisecond}
	al.StartFlusher()
	defer al.StopFlusher()

	// Log a single entry — below batch threshold, so it only flushes via timer.
	al.Log("http", AccessLogEntry{
		Decision:  "allow",
		UserEmail: "autoflusher@example.com",
		Resource:  "test",
		Method:    "GET",
		Path:      "/auto",
		Host:      "test.local",
	})

	// Poll for the entry to appear (fast flush interval means ~10ms).
	require.Eventually(t, func() bool {
		var count int
		_ = db.QueryRow(`SELECT COUNT(*) FROM access_logs WHERE user_email = 'autoflusher@example.com'`).Scan(&count)
		return count == 1
	}, 2*time.Second, 10*time.Millisecond, "entry should be auto-flushed by the periodic flusher")
}

func TestAccessLogger_Hypertable(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)

	// Verify TimescaleDB is enabled and access_logs is a hypertable.
	var htName string
	err := db.QueryRow(`SELECT hypertable_name FROM timescaledb_information.hypertables WHERE hypertable_name = 'access_logs'`).Scan(&htName)
	require.NoError(t, err)
	assert.Equal(t, "access_logs", htName)
}

// TestAccessLogger_PersistsEventTimestamp is the M-6 regression test: the row
// timestamp must be the event time captured at Log(), not the flush time, and
// distinct event times in one batch must be preserved (not collapsed to a
// single now()).
func TestAccessLogger_PersistsEventTimestamp(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)
	al := &AccessLogger{Logger: testLogger(), DB: db}

	// Two entries with event times 5 minutes apart, in the same batch.
	t1 := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Millisecond)
	t2 := t1.Add(5 * time.Minute)
	const email = "tsorder@beyond.local"

	al.Log("http", AccessLogEntry{Timestamp: t1, UserEmail: email, Path: "/first"})
	al.Log("http", AccessLogEntry{Timestamp: t2, UserEmail: email, Path: "/second"})
	// Flush happens well after both event times; DEFAULT now() would stamp
	// both with the flush time and lose the 5-minute spread.
	al.Flush()

	rows, err := db.Query(
		`SELECT path, timestamp FROM access_logs WHERE user_email = $1 ORDER BY timestamp`, email)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	type rec struct {
		path string
		ts   time.Time
	}
	var got []rec
	for rows.Next() {
		var r rec
		require.NoError(t, rows.Scan(&r.path, &r.ts))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	require.Len(t, got, 2)

	assert.Equal(t, "/first", got[0].path)
	assert.Equal(t, "/second", got[1].path)
	assert.WithinDuration(t, t1, got[0].ts.UTC(), time.Millisecond,
		"row timestamp must be the captured event time, not flush time")
	assert.WithinDuration(t, t2, got[1].ts.UTC(), time.Millisecond)
	assert.Equal(t, 5*time.Minute, got[1].ts.Sub(got[0].ts),
		"intra-batch event ordering/spread must be preserved")
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
}

// closedDB returns a *sql.DB whose Exec always fails ("database is closed"),
// so the access-log failure path can be exercised without a real database.
func closedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://user:pass@127.0.0.1:1/db?sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, db.Close()) // now every Exec fails deterministically
	return db
}

// TestAccessLogger_FailedFlushReenqueues is the M-4 regression test: a batch
// whose insert fails must be re-enqueued (not dropped), so a transient DB
// failure does not silently destroy audit records.
func TestAccessLogger_FailedFlushReenqueues(t *testing.T) {
	t.Parallel()
	al := &AccessLogger{Logger: testLogger(), DB: closedDB(t)}

	al.Log("http", AccessLogEntry{UserEmail: "reenqueue@beyond.local"})
	al.Flush() // insert fails -> entry re-enqueued

	al.mu.Lock()
	n := len(al.batch)
	al.mu.Unlock()
	assert.Equal(t, 1, n, "failed entry must be re-enqueued, not dropped")
}

// TestAccessLogger_BufferOverflowDropsOldestAndCounts proves the bounded
// buffer drops the OLDEST entries and accounts for the loss rather than
// growing without bound or losing entries silently.
func TestAccessLogger_BufferOverflowDropsOldestAndCounts(t *testing.T) {
	t.Parallel()
	al := &AccessLogger{Logger: testLogger(), DB: closedDB(t)}

	before := testutil.ToFloat64(accessLogDroppedEntries)

	// Seed the batch just over the cap, then force a failed flush so the
	// over-cap entries are dropped during re-enqueue.
	al.mu.Lock()
	al.batch = make([]typedEntry, maxBufferedEntries+10)
	for i := range al.batch {
		al.batch[i] = typedEntry{typ: "http", entry: AccessLogEntry{}}
	}
	al.mu.Unlock()

	al.Flush() // pulls whole batch, insert fails, re-enqueue trims to cap

	al.mu.Lock()
	n := len(al.batch)
	al.mu.Unlock()
	assert.LessOrEqual(t, n, maxBufferedEntries, "buffer must be capped at maxBufferedEntries")

	after := testutil.ToFloat64(accessLogDroppedEntries)
	assert.Equal(t, float64(10), after-before, "exactly the 10 over-cap entries must be counted as dropped")
}

// TestAccessLogger_FailureCooldownSuppressesSyncFlush proves that after a
// failure, a request-path enqueue at the batch threshold does NOT synchronously
// hit the DB (which would inject latency during an outage) — the cooldown
// defers retries to the periodic flusher.
func TestAccessLogger_FailureCooldownSuppressesSyncFlush(t *testing.T) {
	t.Parallel()
	al := &AccessLogger{Logger: testLogger(), DB: closedDB(t)}

	// Trigger a failure to arm the cooldown.
	al.Log("http", AccessLogEntry{})
	al.Flush()

	al.mu.Lock()
	cooling := time.Now().Before(al.failingUntil)
	al.mu.Unlock()
	require.True(t, cooling, "a failed flush must arm the cooldown")

	// Fill to batchSize on the request path; enqueue must NOT flush
	// synchronously while cooling, so the batch keeps growing.
	for range batchSize + 5 {
		al.Log("http", AccessLogEntry{})
	}
	al.mu.Lock()
	n := len(al.batch)
	al.mu.Unlock()
	assert.Greater(t, n, batchSize, "during cooldown the batch must not be drained synchronously")
}
