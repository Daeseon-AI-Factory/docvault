ALTER TABLE install_tokens DROP CONSTRAINT IF EXISTS fk_install_tokens_used_agent;

ALTER TABLE endpoint_agents
    DROP COLUMN IF EXISTS last_clipboard_event_at,
    DROP COLUMN IF EXISTS last_self_test_at,
    DROP COLUMN IF EXISTS clipboard_error,
    DROP COLUMN IF EXISTS clipboard_available,
    DROP COLUMN IF EXISTS health_status,
    DROP COLUMN IF EXISTS session_username,
    DROP COLUMN IF EXISTS running_mode,
    DROP COLUMN IF EXISTS agent_version,
    DROP COLUMN IF EXISTS install_token_id;

DROP TABLE IF EXISTS install_tokens;
