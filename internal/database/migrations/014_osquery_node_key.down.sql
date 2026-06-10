DROP INDEX IF EXISTS idx_endpoint_agents_node_key;
ALTER TABLE endpoint_agents DROP COLUMN IF EXISTS node_key;
