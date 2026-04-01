-- User & Entity Behavior Analytics (UEBA)

-- Per-user behavioral baseline (recalculated daily)
CREATE TABLE user_behavior_baselines (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Time patterns
    avg_daily_events REAL NOT NULL DEFAULT 0,          -- average events per day
    avg_daily_downloads REAL NOT NULL DEFAULT 0,       -- average file downloads per day
    typical_start_hour SMALLINT NOT NULL DEFAULT 8,    -- earliest typical activity hour (0-23)
    typical_end_hour SMALLINT NOT NULL DEFAULT 19,     -- latest typical activity hour (0-23)
    works_weekends BOOLEAN NOT NULL DEFAULT false,     -- true if regularly active on weekends
    -- Access patterns
    known_ips TEXT[] NOT NULL DEFAULT '{}',             -- array of known IP addresses
    known_hostnames TEXT[] NOT NULL DEFAULT '{}',       -- known endpoint hostnames
    frequent_file_types TEXT[] NOT NULL DEFAULT '{}',   -- file extensions commonly accessed
    -- Calculated at
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Risk score history (one row per user per day)
CREATE TABLE risk_scores (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score INTEGER NOT NULL DEFAULT 0,                  -- 0-100
    factors JSONB NOT NULL DEFAULT '[]',               -- array of {factor, weight, detail}
    scored_at DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(user_id, scored_at)
);
CREATE INDEX idx_risk_scores_date ON risk_scores(scored_at DESC);
CREATE INDEX idx_risk_scores_user ON risk_scores(user_id, scored_at DESC);

-- Anomaly events (individual detections that contribute to risk score)
CREATE TABLE anomaly_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    anomaly_type VARCHAR(50) NOT NULL,    -- 'after_hours', 'bulk_download', 'new_ip', 'ext_disguise', 'weekend_access', 'unusual_filetype'
    severity VARCHAR(20) NOT NULL,         -- 'low', 'medium', 'high', 'critical'
    detail TEXT NOT NULL DEFAULT '',
    source_event_id INTEGER,              -- reference to endpoint_events.id or audit_logs.id
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_anomaly_events_user ON anomaly_events(user_id, detected_at DESC);
CREATE INDEX idx_anomaly_events_type ON anomaly_events(anomaly_type);
