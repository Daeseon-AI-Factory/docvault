CREATE TABLE endpoint_agents (
    id BIGSERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    user_id BIGINT REFERENCES users(id),
    source VARCHAR(20) NOT NULL DEFAULT 'osquery' CHECK (source IN ('osquery', 'clipboard')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_checkin TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(hostname, source)
);

CREATE INDEX idx_endpoint_agents_hostname ON endpoint_agents(hostname);
CREATE INDEX idx_endpoint_agents_user ON endpoint_agents(user_id);
