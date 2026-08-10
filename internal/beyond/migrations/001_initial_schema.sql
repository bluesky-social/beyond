-- +goose Up

-- Access logs: stores HTTP proxy request events.
CREATE TABLE IF NOT EXISTS access_logs (
    timestamp       timestamptz NOT NULL DEFAULT now(),
    type            text NOT NULL,
    decision        text NOT NULL,
    user_email      text NOT NULL DEFAULT '',
    user_groups     text[] NOT NULL DEFAULT '{}',
    resource        text NOT NULL DEFAULT '',
    upstream        text NOT NULL DEFAULT '',
    method          text NOT NULL DEFAULT '',
    path            text NOT NULL DEFAULT '',
    host            text NOT NULL DEFAULT '',
    source_ip       text NOT NULL DEFAULT '',
    user_agent      text NOT NULL DEFAULT '',
    status_code     int NOT NULL DEFAULT 0,
    duration_ms     int NOT NULL DEFAULT 0,
    bytes_sent      bigint NOT NULL DEFAULT 0,
    session_id      text NOT NULL DEFAULT '',
    error           text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_user_email ON access_logs (user_email, timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_decision ON access_logs (decision, timestamp);

-- +goose Down
DROP TABLE IF EXISTS access_logs;
