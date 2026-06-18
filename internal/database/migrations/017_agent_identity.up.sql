ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS reported_username VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_ip VARCHAR(64) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_endpoint_agents_reported_username ON endpoint_agents(reported_username);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_last_ip ON endpoint_agents(last_ip);
