package beyond

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
)

const (
	batchSize     = 100
	flushInterval = 5 * time.Second

	// maxBufferedEntries caps the in-memory batch (pending + re-enqueued
	// failed entries). The audit trail is beyond's primary access-logging
	// mechanism, so a transient DB blip must not lose entries: a failed batch
	// is re-enqueued and retried by the next flush. But the buffer cannot grow
	// without bound during a sustained outage — that would OOM the proxy and
	// take down request serving (a worse failure than losing audit rows). When
	// the buffer is full we drop the OLDEST entries and increment
	// accessLogDroppedEntries so the loss is alertable. Sized to bound memory
	// at roughly maxBufferedEntries * sizeof(entry) ~ a few MB.
	maxBufferedEntries = 50_000
)

// AccessLogEntry holds structured data for a single access log event.
type AccessLogEntry struct {
	// Timestamp is the event time, captured in-process when the entry is
	// logged. It is set by Log() if unset. Persisting it explicitly (rather
	// than relying on the column's DEFAULT now(), which evaluates at flush
	// time) keeps the true event time and preserves intra-batch ordering — a
	// whole batch would otherwise share one identical flush-time timestamp.
	Timestamp  time.Time
	Decision   string
	UserEmail  string
	UserGroups []string
	Resource   string
	Upstream   string
	Method     string
	Path       string
	Host       string
	SourceIP   string
	UserAgent  string
	StatusCode int
	DurationMS int
	BytesSent  int64
	SessionID  string
	Error      string
}

// typedEntry couples an AccessLogEntry with its event type for batch storage.
type typedEntry struct {
	typ   string
	entry AccessLogEntry
}

// AccessLogger logs access events to slog immediately and batches them for DB insertion.
// Call StartFlusher to begin periodic flushes; call Flush on shutdown.
type AccessLogger struct {
	Logger        *slog.Logger
	DB            *sql.DB
	FlushInterval time.Duration // 0 means use default (5s)
	mu            sync.Mutex
	batch         []typedEntry
	stop          chan struct{}

	// failingUntil suppresses synchronous (request-path) batch-size flushes
	// after a write failure: during a DB outage the batch refills to batchSize
	// on nearly every request, so without this each request would synchronously
	// retry the DB — hammering it and injecting connect-timeout latency onto
	// request serving. The periodic flusher keeps retrying off the request
	// path. Guarded by mu.
	failingUntil time.Time
}

// flushFailureCooldown is how long synchronous request-path flushes are
// suppressed after a failed write (the periodic flusher still retries).
const flushFailureCooldown = 5 * time.Second

// StartFlusher begins a background goroutine that flushes the batch to the DB
// periodically. Call this once after construction if DB is configured.
func (al *AccessLogger) StartFlusher() {
	if al.DB == nil {
		return
	}
	interval := al.FlushInterval
	if interval == 0 {
		interval = flushInterval
	}
	al.stop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				al.Flush()
			case <-al.stop:
				return
			}
		}
	}()
}

// StopFlusher stops the background flusher and performs a final flush.
func (al *AccessLogger) StopFlusher() {
	if al.stop != nil {
		close(al.stop)
	}
	al.Flush()
}

// Log logs an access event to slog at debug level and, if a DB is configured,
// queues it for batch insertion to TimescaleDB (the primary access logging mechanism).
func (al *AccessLogger) Log(typ string, entry AccessLogEntry) {
	// Capture event time at log time, not flush time. Callers may set it
	// explicitly (e.g. to the request start); otherwise stamp now.
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	al.Logger.Debug("access",
		"type", typ,
		"decision", entry.Decision,
		"user_email", entry.UserEmail,
		"user_groups", entry.UserGroups,
		"resource", entry.Resource,
		"upstream", entry.Upstream,
		"method", entry.Method,
		"path", entry.Path,
		"host", entry.Host,
		"source_ip", entry.SourceIP,
		"user_agent", entry.UserAgent,
		"status_code", entry.StatusCode,
		"duration_ms", entry.DurationMS,
		"bytes_sent", entry.BytesSent,
		"session_id", entry.SessionID,
		"error", entry.Error,
	)
	al.enqueue(typ, entry)
}

// Flush writes any remaining batched entries to the database.
func (al *AccessLogger) Flush() {
	if al.DB == nil {
		return
	}
	al.mu.Lock()
	entries := al.batch
	al.batch = nil
	al.mu.Unlock()

	if len(entries) > 0 {
		al.writeBatch(entries)
	}
}

// enqueue adds an entry to the typed batch. If the batch reaches batchSize it is flushed automatically.
func (al *AccessLogger) enqueue(typ string, entry AccessLogEntry) {
	if al.DB == nil {
		return
	}

	al.mu.Lock()
	al.batch = append(al.batch, typedEntry{typ: typ, entry: entry})
	var toFlush []typedEntry
	// Only flush synchronously on the request path when we're at the batch
	// threshold AND not in a post-failure cooldown. During an outage the batch
	// stays at/above batchSize, so this guard is what keeps a slow/erroring DB
	// from injecting latency onto every request — the periodic flusher retries
	// instead. Cap the synchronous flush so the batch can still drain even if
	// it has grown past batchSize via re-enqueued failures.
	if len(al.batch) >= batchSize && time.Now().After(al.failingUntil) {
		n := min(len(al.batch), batchSize)
		toFlush = al.batch[:n:n]
		al.batch = al.batch[n:]
	}
	al.mu.Unlock()

	if toFlush != nil {
		al.writeBatch(toFlush)
	}
}

// writeBatch inserts a slice of typed entries into access_logs using a single
// multi-row INSERT for efficiency.
func (al *AccessLogger) writeBatch(entries []typedEntry) {
	if len(entries) == 0 {
		return
	}
	start := time.Now()
	defer func() {
		accessLogFlushDuration.Observe(time.Since(start).Seconds())
		accessLogFlushSize.Observe(float64(len(entries)))
	}()

	const cols = 17
	var b strings.Builder
	b.WriteString(`INSERT INTO access_logs (
		timestamp, type, decision, user_email, user_groups,
		resource, upstream, method, path, host,
		source_ip, user_agent, status_code, duration_ms, bytes_sent,
		session_id, error
	) VALUES `)

	args := make([]any, 0, len(entries)*cols)
	for i, te := range entries {
		e := te.entry
		// Ensure user_groups is never nil — pq.Array(nil) sends SQL NULL
		// which violates the NOT NULL constraint.
		if e.UserGroups == nil {
			e.UserGroups = []string{}
		}
		if i > 0 {
			b.WriteString(", ")
		}
		base := i * cols
		b.WriteByte('(')
		for j := 1; j <= cols; j++ {
			if j > 1 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "$%d", base+j)
		}
		b.WriteByte(')')
		args = append(args,
			e.Timestamp, te.typ, e.Decision, e.UserEmail, pq.Array(e.UserGroups),
			e.Resource, e.Upstream, e.Method, e.Path, e.Host,
			e.SourceIP, e.UserAgent, e.StatusCode, e.DurationMS, e.BytesSent,
			e.SessionID, e.Error,
		)
	}

	if _, err := al.DB.Exec(b.String(), args...); err != nil {
		// Re-enqueue rather than drop: the audit trail is the primary access
		// logging mechanism, and a transient DB blip (failover, pool
		// exhaustion) must not silently destroy records for already-served
		// requests. The next flush retries. The inline retry-with-sleep that
		// used to live here is gone — it injected up to 100ms of latency onto
		// the request goroutine whenever a batch-size flush failed.
		al.Logger.Error("access log batch insert failed, re-enqueued for retry", "error", err, "count", len(entries))
		al.requeue(entries)
	}
}

// requeue prepends a failed batch back onto the pending batch so the next
// flush retries it (failed entries are older, so they go first to preserve
// rough ordering). The combined buffer is capped at maxBufferedEntries: under
// a sustained DB outage we drop the OLDEST entries and increment
// accessLogDroppedEntries rather than growing memory without bound and OOMing
// the proxy. Dropping is the explicit, alertable fallback — never silent.
func (al *AccessLogger) requeue(failed []typedEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.failingUntil = time.Now().Add(flushFailureCooldown)

	combined := append(failed, al.batch...)
	if len(combined) > maxBufferedEntries {
		dropped := len(combined) - maxBufferedEntries
		combined = combined[dropped:] // drop oldest
		accessLogDroppedEntries.Add(float64(dropped))
		al.Logger.Error("access log retry buffer full, dropped oldest entries",
			"dropped", dropped, "buffer_cap", maxBufferedEntries)
	}
	al.batch = combined
}
