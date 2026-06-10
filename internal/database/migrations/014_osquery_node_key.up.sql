-- osquery TLS enrollment.
-- A node enrolls at /api/osquery/enroll with the shared enroll secret and is
-- issued a node_key, which it then presents on /api/osquery/config and
-- /api/osquery/log. We store the node_key on the existing endpoint_agents row
-- (source = 'osquery') so config/log requests can resolve hostname + user.
ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS node_key VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_node_key ON endpoint_agents(node_key);
