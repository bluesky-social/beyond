package beyond

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProxyServer_NoAbsoluteWriteOrReadTimeout is the H-1 config guard.
// The whole-connection ReadTimeout/WriteTimeout must be disabled (they sever
// streaming responses and cap large uploads); the handshake stays bounded by
// ReadHeaderTimeout.
func TestNewProxyServer_NoAbsoluteWriteOrReadTimeout(t *testing.T) {
	t.Parallel()
	srv := newProxyServer(":0", http.NewServeMux())
	assert.Zero(t, srv.WriteTimeout, "WriteTimeout must be 0 so SSE/streaming responses aren't severed")
	assert.Zero(t, srv.ReadTimeout, "ReadTimeout must be 0 so slow/large uploads aren't capped")
	assert.Equal(t, proxyReadHeaderTimeout, srv.ReadHeaderTimeout, "handshake must stay bounded")
	assert.NotZero(t, srv.IdleTimeout, "keep-alive idle connections must still be reclaimed")
}

// TestResponseWriter_StreamSurvivesPastIdleWindow proves a steadily-flushing
// SSE-style stream survives far longer than the idle write window — the
// behavior the old absolute WriteTimeout broke. With a 200ms idle window we
// stream for ~1s (5x the window), flushing every 80ms; every event must be
// delivered.
func TestResponseWriter_StreamSurvivesPastIdleWindow(t *testing.T) {
	t.Parallel()

	const (
		idle      = 200 * time.Millisecond
		interval  = 80 * time.Millisecond
		numEvents = 12 // ~960ms total, ~5x the idle window
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rw := newResponseWriterWithIdle(w, idle)
		rw.Header().Set("Content-Type", "text/event-stream")
		rw.WriteHeader(http.StatusOK)
		for range numEvents {
			if _, err := rw.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			rw.Flush()
			time.Sleep(interval)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Count delivered events by scanning "data:" lines.
	sc := bufio.NewScanner(resp.Body)
	var got int
	for sc.Scan() {
		if len(sc.Text()) >= 5 && sc.Text()[:5] == "data:" {
			got++
		}
	}
	require.NoError(t, sc.Err(), "stream must not be severed mid-flight")
	assert.Equal(t, numEvents, got,
		"every flushed event must be delivered; the idle deadline must re-arm on each flush")
}

// TestResponseWriter_StalledStreamHitsIdleDeadline proves the replacement
// guard still does its job: a response that stops writing while the client
// stops reading (TCP backpressure) is reclaimed after the idle window rather
// than hanging forever. We fill the socket buffer then block in a single
// large Write; with a short idle deadline that Write must eventually error.
func TestResponseWriter_StalledStreamHitsIdleDeadline(t *testing.T) {
	t.Parallel()

	const idle = 200 * time.Millisecond

	writeErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rw := newResponseWriterWithIdle(w, idle)
		rw.WriteHeader(http.StatusOK)
		rw.Flush()
		// A 64MB body the client never reads: once kernel + TLS buffers fill,
		// Write blocks and the idle write deadline must fire.
		big := make([]byte, 64<<20)
		_, err := rw.Write(big)
		writeErr <- err
	}))
	defer srv.Close()

	// Open the connection, read the headers, then deliberately stop reading.
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)

	select {
	case err := <-writeErr:
		require.Error(t, err, "a stalled write must hit the idle deadline, not block forever")
		assert.True(t, errors.Is(err, context.DeadlineExceeded) || isTimeout(err),
			"error should be a deadline/timeout, got: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("stalled write was not reclaimed by the idle deadline")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestCountingConn_ConcurrentWriteAndReadIsRaceFree models the M-10 race the
// PR review caught: after a hijacked upgrade, httputil's
// handleUpgradeResponse can return (and the handler read bytesWritten) while
// the surviving client-bound copy goroutine is still calling
// countingConn.Write. The atomic counter must make that read/write race-free
// (run under -race to enforce). Asserts no bytes are lost, either.
func TestCountingConn_ConcurrentWriteAndReadIsRaceFree(t *testing.T) {
	t.Parallel()

	rw := &responseWriter{}
	cc := &countingConn{Conn: discardConn{}, written: &rw.bytesWritten}

	const writes = 1000
	done := make(chan struct{})
	go func() {
		for range writes {
			_, _ = cc.Write([]byte("x"))
		}
		close(done)
	}()
	// Concurrently read the counter, as the handler would post-ServeHTTP.
	for {
		select {
		case <-done:
			assert.Equal(t, int64(writes), rw.bytesWritten.Load(),
				"every byte written by the surviving copier must be counted")
			return
		default:
			_ = rw.bytesWritten.Load()
		}
	}
}

// discardConn is a net.Conn whose Write succeeds and discards, for exercising
// countingConn without a real socket.
type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error) { return len(b), nil }

// TestResponseWriter_HijackRecordsUpgradeStatusAndBytes is the M-10 regression
// test. After a connection is hijacked for a protocol upgrade, the access log
// must record status 101 and the real bytes streamed to the client — not the
// init 200 / 0 bytes that the old wrapper reported (the stdlib writes the 101
// and all bytes straight to the raw conn, bypassing WriteHeader/Write).
func TestResponseWriter_HijackRecordsUpgradeStatusAndBytes(t *testing.T) {
	t.Parallel()

	payload := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nstreamed-bytes")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rw := newResponseWriter(w)
		conn, _, err := rw.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = conn.Write(payload)
		_ = conn.Close()

		// Assertions on the recorded outcome, made inside the handler since
		// the responseWriter is local to it.
		assert.Equal(t, http.StatusSwitchingProtocols, rw.statusCode,
			"hijacked upgrade must record status 101, not the init 200")
		assert.Equal(t, "upgrade", proxyDecision(rw), "decision must be upgrade")
		assert.Equal(t, int64(len(payload)), rw.bytesWritten.Load(),
			"bytes streamed over the hijacked conn must be counted, not 0")
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	require.NoError(t, err)

	// Drain so the handler's write completes and its assertions run.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(conn)
}

// TestResponseWriter_HijackClearsDeadline proves that hijacking (WebSocket/h2c)
// clears the idle write deadline so the long-lived tunnel isn't severed.
func TestResponseWriter_HijackClearsDeadline(t *testing.T) {
	t.Parallel()

	const idle = 150 * time.Millisecond

	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rw := newResponseWriterWithIdle(w, idle)
		conn, _, err := rw.Hijack()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		// Sleep well past the idle window, then write. If Hijack failed to
		// clear the deadline this write would time out.
		time.Sleep(4 * idle)
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
		done <- err
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)

	select {
	case err := <-done:
		assert.NoError(t, err, "write after hijack must succeed past the idle window (deadline cleared)")
	case <-time.After(10 * time.Second):
		t.Fatal("hijacked handler did not complete")
	}
}
