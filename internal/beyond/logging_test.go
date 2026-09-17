package beyond

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
}

type recordingAccessLogSink struct {
	mu      sync.Mutex
	records []AccessLogRecord
	calls   int
	err     error
	entered chan struct{}
	release chan struct{}
}

func (s *recordingAccessLogSink) WriteAccessLogs(ctx context.Context, records []AccessLogRecord) error {
	s.mu.Lock()
	s.calls++
	err := s.err
	entered, release := s.entered, s.release
	if err == nil {
		s.records = append(s.records, append([]AccessLogRecord(nil), records...)...)
	}
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (s *recordingAccessLogSink) snapshot() ([]AccessLogRecord, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AccessLogRecord(nil), s.records...), s.calls
}

func TestAccessLoggerFlushesCompleteRecord(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{}
	al := &AccessLogger{Logger: testLogger(), Sink: sink}
	wantTime := time.Date(2026, time.September, 17, 12, 34, 56, 789000000, time.UTC)
	al.Log("http", AccessLogEntry{
		Timestamp: wantTime, Decision: "allow", UserEmail: "bob@example.com",
		UserGroups: []string{"platform"}, Resource: "argocd",
		Upstream: "http://localhost:8080", Method: "POST", Path: "/api/v1/sync",
		Host: "argocd.internal", SourceIP: "10.0.0.2", UserAgent: "argocd-cli/2.0",
		StatusCode: 202, DurationMS: 13, BytesSent: 512, SessionID: "sess-xyz",
		Error: "none",
	})
	al.Flush()

	records, calls := sink.snapshot()
	require.Equal(t, 1, calls)
	require.Len(t, records, 1)
	assert.Equal(t, "http", records[0].Type)
	assert.Equal(t, wantTime, records[0].Entry.Timestamp)
	assert.Equal(t, "bob@example.com", records[0].Entry.UserEmail)
	assert.Equal(t, []string{"platform"}, records[0].Entry.UserGroups)
	assert.Equal(t, int64(512), records[0].Entry.BytesSent)
}

func TestAccessLoggerAutoFlush(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{}
	al := &AccessLogger{Logger: testLogger(), Sink: sink, FlushInterval: 5 * time.Millisecond}
	al.StartFlusher()
	defer al.StopFlusher()
	al.Log("http", AccessLogEntry{UserEmail: "autoflusher@example.com"})
	require.Eventually(t, func() bool {
		records, _ := sink.snapshot()
		return len(records) == 1
	}, time.Second, 5*time.Millisecond)
}

func TestAccessLoggerThresholdFlushIsOffRequestPath(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{entered: make(chan struct{}, 1), release: make(chan struct{})}
	al := &AccessLogger{Logger: testLogger(), Sink: sink, FlushInterval: time.Hour}
	al.StartFlusher()

	start := time.Now()
	for range batchSize {
		al.Log("http", AccessLogEntry{})
	}
	assert.Less(t, time.Since(start), time.Second, "logging must not wait for ClickHouse")
	require.Eventually(t, func() bool {
		select {
		case <-sink.entered:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
	close(sink.release)
	al.StopFlusher()

	records, calls := sink.snapshot()
	assert.Equal(t, 1, calls)
	assert.Len(t, records, batchSize)
}

func TestAccessLoggerFailedFlushReenqueues(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{err: errors.New("unavailable")}
	al := &AccessLogger{Logger: testLogger(), Sink: sink}
	al.Log("http", AccessLogEntry{UserEmail: "reenqueue@beyond.local"})
	al.Flush()

	al.mu.Lock()
	records := append([]AccessLogRecord(nil), al.batch...)
	al.mu.Unlock()
	require.Len(t, records, 1)
	assert.Equal(t, "reenqueue@beyond.local", records[0].Entry.UserEmail)
}

func TestAccessLoggerEnqueueIsBoundedAndDropsOldest(t *testing.T) {
	// This test observes a process-global metric and therefore cannot be parallel.
	sink := &recordingAccessLogSink{}
	al := &AccessLogger{Logger: testLogger(), Sink: sink}
	before := testutil.ToFloat64(accessLogDroppedEntries)

	for i := range maxBufferedEntries + 10 {
		al.Log("http", AccessLogEntry{BytesSent: int64(i)})
	}

	al.mu.Lock()
	n := len(al.batch)
	oldest := al.batch[0].Entry.BytesSent
	newest := al.batch[len(al.batch)-1].Entry.BytesSent
	al.mu.Unlock()
	assert.Equal(t, maxBufferedEntries, n)
	assert.Equal(t, int64(10), oldest)
	assert.Equal(t, int64(maxBufferedEntries+9), newest)
	after := testutil.ToFloat64(accessLogDroppedEntries)
	assert.Equal(t, float64(10), after-before)
}

func TestAccessLoggerFailureCooldownSuppressesRetryStorm(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{err: errors.New("unavailable")}
	al := &AccessLogger{Logger: testLogger(), Sink: sink, FlushInterval: time.Hour}
	al.Log("http", AccessLogEntry{})
	al.Flush()
	al.StartFlusher()

	for range batchSize {
		al.Log("http", AccessLogEntry{})
	}
	assert.Never(t, func() bool {
		_, calls := sink.snapshot()
		return calls > 1
	}, 50*time.Millisecond, 5*time.Millisecond, "threshold signals must pause during the failure cooldown")

	sink.mu.Lock()
	sink.err = nil
	sink.mu.Unlock()
	al.StopFlusher()
	records, calls := sink.snapshot()
	assert.Equal(t, 2, calls)
	assert.Len(t, records, batchSize+1)
}

func TestAccessLoggerConcurrentLoggingHasNoLoss(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{}
	al := &AccessLogger{Logger: testLogger(), Sink: sink, FlushInterval: time.Hour}
	al.StartFlusher()

	const goroutines = 20
	const perGoroutine = 250
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perGoroutine {
				al.Log("http", AccessLogEntry{})
			}
		}()
	}
	wg.Wait()
	al.StopFlusher()
	al.StopFlusher()

	records, _ := sink.snapshot()
	assert.Len(t, records, goroutines*perGoroutine)
}

func TestAccessLoggerCapturesEventTimestampAtLogTime(t *testing.T) {
	t.Parallel()
	sink := &recordingAccessLogSink{}
	al := &AccessLogger{Logger: testLogger(), Sink: sink}
	before := time.Now().UTC()
	al.Log("http", AccessLogEntry{})
	after := time.Now().UTC()
	al.Flush()
	records, _ := sink.snapshot()
	require.Len(t, records, 1)
	assert.False(t, records[0].Entry.Timestamp.Before(before))
	assert.False(t, records[0].Entry.Timestamp.After(after))
}
