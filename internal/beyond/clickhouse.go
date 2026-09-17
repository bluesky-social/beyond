package beyond

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

const accessLogRetentionDays = 90

// accessLogSchema is intentionally a single, application-owned table. Monthly
// partitions make retention cheap, while the sorting key serves the common
// "show activity for this user in this time range" audit query without
// creating secondary indexes or materialized views.
const accessLogSchema = `
CREATE TABLE IF NOT EXISTS access_logs
(
    timestamp DateTime64(3, 'UTC'),
    type LowCardinality(String),
    decision LowCardinality(String),
    user_email String,
    user_groups Array(String),
    resource LowCardinality(String),
    upstream String,
    method LowCardinality(String),
    path String,
    host String,
    source_ip String,
    user_agent String,
    status_code Int32,
    duration_ms Int64,
    bytes_sent Int64,
    session_id String,
    error String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (toDate(timestamp), user_email, timestamp)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192
`

// ClickHouseAccessLogStore owns the ClickHouse connection pool used by access
// logging. Beyond has no other persistent application data.
type ClickHouseAccessLogStore struct {
	conn clickhouse.Conn
}

// OpenClickHouseAccessLogStore connects to ClickHouse and creates the access
// log table if needed. The URL uses the driver's standard format, for example
// clickhouse://user:password@host:9440/beyond?secure=true.
func OpenClickHouseAccessLogStore(ctx context.Context, dsn string) (*ClickHouseAccessLogStore, error) {
	options, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing ClickHouse URL: %w", err)
	}
	if options.MaxOpenConns == 0 {
		options.MaxOpenConns = 10
	}
	if options.MaxIdleConns == 0 {
		options.MaxIdleConns = 5
	}
	if options.ConnMaxLifetime == 0 {
		options.ConnMaxLifetime = 30 * time.Minute
	}
	if options.Compression == nil {
		options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("opening ClickHouse: %w", err)
	}
	store := &ClickHouseAccessLogStore{conn: conn}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("connecting to ClickHouse: %w", err)
	}
	if err := store.Initialize(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return store, nil
}

// Initialize applies the idempotent ClickHouse schema.
func (s *ClickHouseAccessLogStore) Initialize(ctx context.Context) error {
	if err := s.conn.Exec(ctx, accessLogSchema); err != nil {
		return fmt.Errorf("creating ClickHouse access_logs table: %w", err)
	}
	return nil
}

// WriteAccessLogs sends one native ClickHouse batch. A batch creates one part,
// so keeping this operation batched is important for sustained ingest rates.
func (s *ClickHouseAccessLogStore) WriteAccessLogs(ctx context.Context, entries []AccessLogRecord) error {
	batch, err := s.conn.PrepareBatch(ctx, `INSERT INTO access_logs (
		timestamp, type, decision, user_email, user_groups,
		resource, upstream, method, path, host,
		source_ip, user_agent, status_code, duration_ms, bytes_sent,
		session_id, error
	)`)
	if err != nil {
		return fmt.Errorf("preparing ClickHouse access-log batch: %w", err)
	}
	defer func() { _ = batch.Close() }()

	for _, record := range entries {
		e := record.Entry
		if e.UserGroups == nil {
			e.UserGroups = []string{}
		}
		if err := batch.Append(
			e.Timestamp, record.Type, e.Decision, e.UserEmail, e.UserGroups,
			e.Resource, e.Upstream, e.Method, e.Path, e.Host,
			e.SourceIP, e.UserAgent, int32(e.StatusCode), int64(e.DurationMS), e.BytesSent,
			e.SessionID, e.Error,
		); err != nil {
			return fmt.Errorf("appending ClickHouse access-log row: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("sending ClickHouse access-log batch: %w", err)
	}
	return nil
}

func (s *ClickHouseAccessLogStore) Close() error {
	return s.conn.Close()
}
