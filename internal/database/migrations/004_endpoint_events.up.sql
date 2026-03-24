CREATE TABLE endpoint_events (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id),
    hostname VARCHAR(255) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    file_name VARCHAR(500) NOT NULL DEFAULT '',
    file_path VARCHAR(1000) NOT NULL DEFAULT '',
    process_name VARCHAR(255) NOT NULL DEFAULT '',
    detail JSONB,
    source VARCHAR(20) NOT NULL DEFAULT 'osquery' CHECK (source IN ('osquery', 'clipboard')),
    event_time TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_endpoint_events_user ON endpoint_events(user_id);
CREATE INDEX idx_endpoint_events_hostname ON endpoint_events(hostname);
CREATE INDEX idx_endpoint_events_type ON endpoint_events(event_type);
CREATE INDEX idx_endpoint_events_time ON endpoint_events(event_time);
CREATE INDEX idx_endpoint_events_file ON endpoint_events(file_name);
