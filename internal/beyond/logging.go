package beyond

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	// Larger batches avoid producing many tiny ClickHouse parts under load.
	batchSize           = 1_000
	flushInterval       = 5 * time.Second
	writeTimeout        = 10 * time.Second
	retryCooldown       = 5 * time.Second
	overflowLogInterval = time.Minute

	// This bounds proxy memory during a sustained ClickHouse outage. The
	// oldest entries are dropped and an alertable metric is incremented.
	maxBufferedEntries = 50_000
)

// AccessLogEntry holds structured data for a single access log event.
type AccessLogEntry struct {
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

// AccessLogRecord couples an access-log event with its event type.
type AccessLogRecord struct {
	Type  string
	Entry AccessLogEntry
}

// AccessLogSink is the storage boundary used by AccessLogger.
type AccessLogSink interface {
	WriteAccessLogs(context.Context, []AccessLogRecord) error
}

// AccessLogger logs access events to slog immediately and asynchronously
// batches them for ClickHouse. Storage I/O never runs on an HTTP request
// goroutine.
type AccessLogger struct {
	Logger        *slog.Logger
	Sink          AccessLogSink
	FlushInterval time.Duration
	// ShutdownRetryInterval is the cadence StopFlusher retries a failed final
	// flush at. Zero means retryCooldown.
	ShutdownRetryInterval time.Duration

	mu              sync.Mutex
	flushMu         sync.Mutex
	batch           []AccessLogRecord
	stop            chan struct{}
	done            chan struct{}
	flushNow        chan struct{}
	stopping        bool
	retryAfter      time.Time
	lastOverflowLog time.Time
}

// StartFlusher begins the single background writer. It is safe to call more
// than once; subsequent calls are no-ops.
func (al *AccessLogger) StartFlusher() {
	if al.Sink == nil {
		return
	}
	al.mu.Lock()
	if al.stop != nil {
		al.mu.Unlock()
		return
	}
	interval := al.FlushInterval
	if interval == 0 {
		interval = flushInterval
	}
	al.stop = make(chan struct{})
	al.done = make(chan struct{})
	al.flushNow = make(chan struct{}, 1)
	stop, done, flushNow := al.stop, al.done, al.flushNow
	al.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-ticker.C:
				al.Flush()
			case <-flushNow:
				al.Flush()
			case <-stop:
				al.Flush()
				return
			}
		}
	}()
}

// StopFlusher stops the background writer and waits for its final flush. If
// that final flush fails and requeues its batch, StopFlusher retries within
// ctx so a transient ClickHouse blip at shutdown does not silently lose the
// last audit records; a genuine outage still terminates when ctx expires
// (bounded by the caller's shutdown deadline, never a private timer). It is
// idempotent, which makes repeated shutdown paths safe.
func (al *AccessLogger) StopFlusher(ctx context.Context) {
	if al.Sink == nil {
		return
	}
	al.mu.Lock()
	if al.stop == nil {
		al.mu.Unlock()
		al.Flush()
		return
	}
	if !al.stopping {
		close(al.stop)
		al.stopping = true
	}
	done := al.done
	al.mu.Unlock()
	<-done

	// The writer's final flush requeues entries on write failure. Retry them
	// on the cooldown cadence until the batch drains or ctx expires.
	retryInterval := al.ShutdownRetryInterval
	if retryInterval == 0 {
		retryInterval = retryCooldown
	}
	for {
		al.mu.Lock()
		pending := len(al.batch)
		al.mu.Unlock()
		if pending == 0 {
			return
		}
		select {
		case <-ctx.Done():
			al.Logger.Error("shutdown flush deadline exceeded, dropping pending access logs",
				"pending", pending)
			accessLogDroppedEntries.Add(float64(pending))
			return
		case <-time.After(retryInterval):
		}
		al.Flush()
	}
}

// Log records an access event locally and queues it for ClickHouse. Timestamp
// is captured here, not at flush time, to preserve true event ordering.
func (al *AccessLogger) Log(typ string, entry AccessLogEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
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
	al.enqueue(AccessLogRecord{Type: typ, Entry: entry})
}

// Flush writes the pending queue as one ClickHouse batch.
func (al *AccessLogger) Flush() {
	if al.Sink == nil {
		return
	}
	al.flushMu.Lock()
	defer al.flushMu.Unlock()
	al.mu.Lock()
	entries := al.batch
	al.batch = nil
	al.mu.Unlock()
	if len(entries) == 0 {
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	err := al.Sink.WriteAccessLogs(ctx, entries)
	cancel()
	accessLogFlushDuration.Observe(time.Since(start).Seconds())
	accessLogFlushSize.Observe(float64(len(entries)))
	if err != nil {
		accessLogWriteFailures.Inc()
		al.Logger.Error("access log batch insert failed, re-enqueued for retry", "error", err, "count", len(entries))
		al.requeue(entries)
	}
}

func (al *AccessLogger) enqueue(record AccessLogRecord) {
	if al.Sink == nil {
		return
	}
	al.mu.Lock()
	al.batch = append(al.batch, record)
	dropped := max(0, len(al.batch)-maxBufferedEntries)
	shouldLogOverflow := false
	if dropped > 0 {
		al.batch = al.batch[dropped:]
		now := time.Now()
		if now.Sub(al.lastOverflowLog) >= overflowLogInterval {
			al.lastOverflowLog = now
			shouldLogOverflow = true
		}
	}
	shouldFlush := len(al.batch) >= batchSize && al.flushNow != nil && time.Now().After(al.retryAfter)
	flushNow := al.flushNow
	al.mu.Unlock()
	if dropped > 0 {
		accessLogDroppedEntries.Add(float64(dropped))
		if shouldLogOverflow {
			al.Logger.Error("access log retry buffer full, dropping oldest entries",
				"dropped", dropped, "buffer_cap", maxBufferedEntries)
		}
	}

	if shouldFlush {
		select {
		case flushNow <- struct{}{}:
		default:
		}
	}
}

// requeue prepends a failed batch so older records retry first. If the bounded
// queue overflows, the oldest records are dropped explicitly and observably.
func (al *AccessLogger) requeue(failed []AccessLogRecord) {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.retryAfter = time.Now().Add(retryCooldown)
	combined := append(failed, al.batch...)
	if len(combined) > maxBufferedEntries {
		dropped := len(combined) - maxBufferedEntries
		combined = combined[dropped:]
		accessLogDroppedEntries.Add(float64(dropped))
		al.Logger.Error("access log retry buffer full, dropped oldest entries",
			"dropped", dropped, "buffer_cap", maxBufferedEntries)
	}
	al.batch = combined
}
