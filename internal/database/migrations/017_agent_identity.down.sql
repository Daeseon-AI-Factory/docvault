DROP INDEX IF EXISTS idx_endpoint_agents_last_ip;
DROP INDEX IF EXISTS idx_endpoint_agents_reported_username;

ALTER TABLE endpoint_agents
    DROP COLUMN IF EXISTS last_ip,
    DROP COLUMN IF EXISTS reported_username;
