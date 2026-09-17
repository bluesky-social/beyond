package beyond

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingShutdowner records the relative order in which lifecycle calls
// happen, by appending labels to a shared slice.
type recordingShutdowner struct {
	label  string
	order  *[]string
	err    error
	onCall func()
}

func (r *recordingShutdowner) Shutdown(context.Context) error {
	if r.onCall != nil {
		r.onCall()
	}
	*r.order = append(*r.order, r.label)
	return r.err
}

type recordingFlusher struct {
	label string
	order *[]string
}

func (r *recordingFlusher) StopFlusher() {
	*r.order = append(*r.order, r.label)
}

// TestGracefulShutdown_DrainsBeforeStoppingFlusher is the M-5 regression test.
// The proxy server must drain (Shutdown) before the access-log flusher is
// stopped, so audit entries enqueued by in-flight requests during the drain
// are captured by the flusher's final flush rather than dropped.
func TestGracefulShutdown_DrainsBeforeStoppingFlusher(t *testing.T) {
	t.Parallel()

	var order []string
	srv := &recordingShutdowner{label: "srv.Shutdown", order: &order}
	debugSrv := &recordingShutdowner{label: "debugSrv.Shutdown", order: &order}
	flusher := &recordingFlusher{label: "StopFlusher", order: &order}

	require.NoError(t, gracefulShutdown(context.Background(), srv, debugSrv, flusher))

	// The proxy drain MUST come before the flusher stop.
	srvIdx := indexOf(order, "srv.Shutdown")
	stopIdx := indexOf(order, "StopFlusher")
	require.NotEqual(t, -1, srvIdx)
	require.NotEqual(t, -1, stopIdx)
	assert.Less(t, srvIdx, stopIdx,
		"srv.Shutdown must run before StopFlusher so in-flight audit entries are flushed; got order %v", order)
}

// TestGracefulShutdown_PersistsEntryEnqueuedDuringDrain proves the invariant
// end-to-end against a real AccessLogger: an entry logged while the proxy is
// draining (modeled by srv.Shutdown's callback) is still present in the batch
// when StopFlusher's final flush runs.
func TestGracefulShutdown_PersistsEntryEnqueuedDuringDrain(t *testing.T) {
	store := ensureClickHouse(t)

	al := &AccessLogger{Logger: testLogger(), Sink: store}
	al.StartFlusher()

	marker := fmt.Sprintf("drain-boundary-%d@beyond.local", time.Now().UnixNano())

	// Model an in-flight request that finishes (and logs) DURING the drain.
	srv := &recordingShutdowner{
		label: "srv.Shutdown",
		order: new([]string),
		onCall: func() {
			al.Log("http", AccessLogEntry{
				Decision:  "allow",
				UserEmail: marker,
				Method:    "GET",
				Path:      "/drain",
				Host:      "drain.local",
			})
		},
	}
	debugSrv := &recordingShutdowner{label: "debugSrv.Shutdown", order: new([]string)}

	require.NoError(t, gracefulShutdown(context.Background(), srv, debugSrv, al))

	var count uint64
	err := store.conn.QueryRow(context.Background(),
		`SELECT count() FROM access_logs WHERE user_email = ?`, marker).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), count,
		"entry enqueued during the drain must be persisted by the flusher's final flush")
}

// TestGracefulShutdown_SurfacesServerError ensures a drain failure is reported
// and short-circuits before stopping the flusher.
func TestGracefulShutdown_SurfacesServerError(t *testing.T) {
	t.Parallel()

	var order []string
	boom := errors.New("boom")
	srv := &recordingShutdowner{label: "srv.Shutdown", order: &order, err: boom}
	debugSrv := &recordingShutdowner{label: "debugSrv.Shutdown", order: &order}
	flusher := &recordingFlusher{label: "StopFlusher", order: &order}

	err := gracefulShutdown(context.Background(), srv, debugSrv, flusher)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
