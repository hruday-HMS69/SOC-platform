CREATE TABLE IF NOT EXISTS log_events (
    id          UUID PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip   VARCHAR(45) NOT NULL,
    event_type  VARCHAR(100) NOT NULL,
    username    VARCHAR(100),
    message     TEXT NOT NULL,
    severity    VARCHAR(20) NOT NULL,
    raw         JSONB
);

CREATE INDEX IF NOT EXISTS idx_log_events_source_ip
    ON log_events(source_ip);

CREATE INDEX IF NOT EXISTS idx_log_events_event_type
    ON log_events(event_type);

CREATE INDEX IF NOT EXISTS idx_log_events_created_at
    ON log_events(created_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id            UUID PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_name     VARCHAR(100) NOT NULL,
    severity      VARCHAR(20) NOT NULL,
    source_ip     VARCHAR(45) NOT NULL,
    description   TEXT NOT NULL,
    log_event_id  UUID NOT NULL REFERENCES log_events(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
    ON alerts(source_ip);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts(created_at DESC);