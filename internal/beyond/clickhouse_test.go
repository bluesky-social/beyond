package beyond

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ensureClickHouse(t *testing.T) *ClickHouseAccessLogStore {
	t.Helper()
	dsn := os.Getenv("BEYOND_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("BEYOND_CLICKHOUSE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := OpenClickHouseAccessLogStore(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestAccessLogSchemaIsSimpleAndBounded(t *testing.T) {
	t.Parallel()
	normalized := strings.Join(strings.Fields(accessLogSchema), " ")
	assert.Contains(t, normalized, "ENGINE = MergeTree")
	assert.Contains(t, normalized, "PARTITION BY toYYYYMM(timestamp)")
	assert.Contains(t, normalized, "ORDER BY (toDate(timestamp), user_email, timestamp)")
	assert.Contains(t, normalized, "TTL timestamp + INTERVAL 90 DAY DELETE")
	assert.NotContains(t, normalized, "Nullable")
	assert.Equal(t, 90, accessLogRetentionDays)
}

func TestClickHouseSchemaAndInitialization(t *testing.T) {
	store := ensureClickHouse(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, store.Initialize(ctx), "schema initialization must be idempotent")

	var engine, partitionKey, sortingKey, createQuery string
	err := store.conn.QueryRow(ctx, `
		SELECT engine, partition_key, sorting_key, create_table_query
		FROM system.tables
		WHERE database = currentDatabase() AND name = 'access_logs'
	`).Scan(&engine, &partitionKey, &sortingKey, &createQuery)
	require.NoError(t, err)
	assert.Equal(t, "MergeTree", engine)
	assert.Equal(t, "toYYYYMM(timestamp)", partitionKey)
	assert.Equal(t, "toDate(timestamp), user_email, timestamp", sortingKey)
	assert.Contains(t, createQuery, "TTL timestamp + toIntervalDay(90)")
}

func TestClickHouseWritePreservesAllFields(t *testing.T) {
	store := ensureClickHouse(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	marker := "integration-" + time.Now().UTC().Format("20060102150405.000000000") + "@beyond.local"
	ts := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	record := AccessLogRecord{Type: "http", Entry: AccessLogEntry{
		Timestamp: ts, Decision: "allow", UserEmail: marker,
		UserGroups: []string{"engineering", "ops"}, Resource: "grafana",
		Upstream: "http://grafana:3000", Method: "GET", Path: "/dashboards/1",
		Host: "grafana.example.com", SourceIP: "2001:db8::1", UserAgent: "test-agent",
		StatusCode: 200, DurationMS: 42, BytesSent: 1234, SessionID: "session-1",
	}}
	emptyGroupsRecord := AccessLogRecord{Type: "http", Entry: AccessLogEntry{
		Timestamp: ts.Add(time.Millisecond), UserEmail: marker + "-empty-groups",
	}}
	require.NoError(t, store.WriteAccessLogs(ctx, []AccessLogRecord{record, emptyGroupsRecord}))

	var got AccessLogEntry
	var gotType string
	var gotStatus int32
	var gotDuration int64
	err := store.conn.QueryRow(ctx, `
		SELECT timestamp, type, decision, user_email, user_groups, resource,
		       upstream, method, path, host, source_ip, user_agent, status_code,
		       duration_ms, bytes_sent, session_id, error
		FROM access_logs WHERE user_email = ? ORDER BY timestamp DESC LIMIT 1
	`, marker).Scan(
		&got.Timestamp, &gotType, &got.Decision, &got.UserEmail, &got.UserGroups,
		&got.Resource, &got.Upstream, &got.Method, &got.Path, &got.Host,
		&got.SourceIP, &got.UserAgent, &gotStatus, &gotDuration,
		&got.BytesSent, &got.SessionID, &got.Error,
	)
	require.NoError(t, err)
	got.StatusCode = int(gotStatus)
	got.DurationMS = int(gotDuration)
	assert.Equal(t, record.Type, gotType)
	assert.Equal(t, record.Entry, got)

	var groups []string
	err = store.conn.QueryRow(ctx,
		`SELECT user_groups FROM access_logs WHERE user_email = ? LIMIT 1`,
		emptyGroupsRecord.Entry.UserEmail).Scan(&groups)
	require.NoError(t, err)
	assert.Empty(t, groups, "nil groups must be encoded as an empty non-null array")
}
