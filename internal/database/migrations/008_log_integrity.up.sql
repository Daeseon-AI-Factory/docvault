-- Log Integrity for Legal Evidence
-- Each log entry contains the SHA-256 hash of the previous entry,
-- forming a tamper-evident chain. If any row is modified/deleted,
-- the chain breaks and the tampering is detectable.

-- Add hash chain columns to endpoint_events
ALTER TABLE endpoint_events
    ADD COLUMN prev_hash VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN row_hash VARCHAR(64) NOT NULL DEFAULT '';

-- Add hash chain columns to audit_logs
ALTER TABLE audit_logs
    ADD COLUMN prev_hash VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN row_hash VARCHAR(64) NOT NULL DEFAULT '';

-- Index for hash chain verification
CREATE INDEX idx_endpoint_events_hash ON endpoint_events(row_hash);
CREATE INDEX idx_audit_logs_hash ON audit_logs(row_hash);

-- Prevent UPDATE on endpoint_events (immutable audit trail)
CREATE OR REPLACE FUNCTION prevent_log_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log entries are immutable and cannot be modified. Row ID: %', OLD.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Prevent DELETE on endpoint_events (immutable audit trail)
CREATE OR REPLACE FUNCTION prevent_log_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log entries are immutable and cannot be deleted. Row ID: %', OLD.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply immutability triggers to endpoint_events
CREATE TRIGGER trg_endpoint_events_no_update
    BEFORE UPDATE ON endpoint_events
    FOR EACH ROW EXECUTE FUNCTION prevent_log_update();

CREATE TRIGGER trg_endpoint_events_no_delete
    BEFORE DELETE ON endpoint_events
    FOR EACH ROW EXECUTE FUNCTION prevent_log_delete();

-- Apply immutability triggers to audit_logs
CREATE TRIGGER trg_audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_log_update();

CREATE TRIGGER trg_audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_log_delete();

-- Auto-compute hash chain on INSERT for endpoint_events
CREATE OR REPLACE FUNCTION compute_endpoint_hash()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash_val VARCHAR(64);
BEGIN
    -- Get the hash of the most recent entry
    SELECT row_hash INTO prev_hash_val
    FROM endpoint_events
    ORDER BY id DESC LIMIT 1;

    IF prev_hash_val IS NULL THEN
        prev_hash_val := '0000000000000000000000000000000000000000000000000000000000000000';
    END IF;

    NEW.prev_hash := prev_hash_val;
    -- Hash = SHA-256(prev_hash + id + user_id + hostname + event_type + file_name + event_time)
    NEW.row_hash := encode(
        digest(
            prev_hash_val || '|' ||
            COALESCE(NEW.user_id::TEXT, 'NULL') || '|' ||
            NEW.hostname || '|' ||
            NEW.event_type || '|' ||
            NEW.file_name || '|' ||
            NEW.file_path || '|' ||
            NEW.process_name || '|' ||
            NEW.source || '|' ||
            NEW.event_time::TEXT,
            'sha256'
        ),
        'hex'
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Auto-compute hash chain on INSERT for audit_logs
CREATE OR REPLACE FUNCTION compute_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash_val VARCHAR(64);
BEGIN
    SELECT row_hash INTO prev_hash_val
    FROM audit_logs
    ORDER BY id DESC LIMIT 1;

    IF prev_hash_val IS NULL THEN
        prev_hash_val := '0000000000000000000000000000000000000000000000000000000000000000';
    END IF;

    NEW.prev_hash := prev_hash_val;
    NEW.row_hash := encode(
        digest(
            prev_hash_val || '|' ||
            COALESCE(NEW.user_id::TEXT, 'NULL') || '|' ||
            NEW.action || '|' ||
            COALESCE(NEW.target_type, '') || '|' ||
            COALESCE(NEW.target_id::TEXT, 'NULL') || '|' ||
            COALESCE(NEW.target_name, '') || '|' ||
            COALESCE(NEW.ip_address, '') || '|' ||
            NEW.status_code::TEXT,
            'sha256'
        ),
        'hex'
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_endpoint_events_hash
    BEFORE INSERT ON endpoint_events
    FOR EACH ROW EXECUTE FUNCTION compute_endpoint_hash();

CREATE TRIGGER trg_audit_logs_hash
    BEFORE INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION compute_audit_hash();

-- Note: requires pgcrypto extension for digest()
CREATE EXTENSION IF NOT EXISTS pgcrypto;
