-- Records every mutating action the AI assistant performs, with enough state to
-- undo it. Powers one-click rollback of agent actions.
CREATE TABLE agent_actions (
    id           BIGSERIAL PRIMARY KEY,
    action_type  VARCHAR(40) NOT NULL,          -- create_user | assign_host | acknowledge_alert
    target_id    BIGINT,                        -- affected entity id (user/agent/alert)
    summary      TEXT NOT NULL,                 -- human-readable description (Korean)
    prev_state   JSONB,                         -- info needed to undo
    performed_by BIGINT REFERENCES users(id),   -- admin who drove the assistant
    undone       BOOLEAN NOT NULL DEFAULT false,
    undone_at    TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_actions_created ON agent_actions (created_at DESC);
