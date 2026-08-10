-- +goose Up
-- +goose StatementBegin

-- Enable TimescaleDB features if the extension is available.
-- On managed PostgreSQL (e.g. AWS RDS) TimescaleDB may not be installed,
-- so this migration is a no-op when the extension is absent.
DO $$
BEGIN
    -- Check if TimescaleDB is available as an installable extension.
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;

        -- Convert to a hypertable partitioned by timestamp.
        PERFORM create_hypertable('access_logs', by_range('timestamp'), migrate_data => true);

        -- Compress chunks older than 7 days.
        ALTER TABLE access_logs SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'user_email,type',
            timescaledb.compress_orderby = 'timestamp DESC'
        );
        PERFORM add_compression_policy('access_logs', INTERVAL '7 days');

        -- Drop chunks older than 90 days.
        PERFORM add_retention_policy('access_logs', INTERVAL '90 days');

        RAISE NOTICE 'TimescaleDB enabled for access_logs';
    ELSE
        RAISE NOTICE 'TimescaleDB not available, skipping hypertable setup';
    END IF;
END
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM remove_retention_policy('access_logs', if_exists => true);
        PERFORM remove_compression_policy('access_logs', if_exists => true);
        DROP EXTENSION IF EXISTS timescaledb CASCADE;
    END IF;
END
$$;
-- +goose StatementEnd
