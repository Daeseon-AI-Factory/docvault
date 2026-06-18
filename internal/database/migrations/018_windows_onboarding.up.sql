CREATE TABLE install_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_hash CHAR(64) NOT NULL UNIQUE,
    user_id BIGINT REFERENCES users(id),
    created_by BIGINT REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_downloaded_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    used_hostname VARCHAR(255) NOT NULL DEFAULT '',
    used_agent_id BIGINT,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_install_tokens_user ON install_tokens(user_id);
CREATE INDEX idx_install_tokens_created ON install_tokens(created_at DESC);
CREATE INDEX idx_install_tokens_expires ON install_tokens(expires_at);

ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS install_token_id BIGINT REFERENCES install_tokens(id),
    ADD COLUMN IF NOT EXISTS agent_version VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS running_mode VARCHAR(40) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS session_user VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS health_status VARCHAR(40) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS clipboard_available BOOLEAN,
    ADD COLUMN IF NOT EXISTS clipboard_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_self_test_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_clipboard_event_at TIMESTAMPTZ;

ALTER TABLE install_tokens
    ADD CONSTRAINT fk_install_tokens_used_agent
    FOREIGN KEY (used_agent_id) REFERENCES endpoint_agents(id);

CREATE INDEX idx_endpoint_agents_health ON endpoint_agents(health_status);
CREATE INDEX idx_endpoint_agents_last_self_test ON endpoint_agents(last_self_test_at DESC);
CREATE INDEX idx_endpoint_agents_last_clipboard_event ON endpoint_agents(last_clipboard_event_at DESC);
