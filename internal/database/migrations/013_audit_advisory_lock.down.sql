-- Revert advisory lock: restore the original (unlocked) trigger functions
-- from migration 008_log_integrity.up.sql.
--
-- Note that the unlocked version is vulnerable to concurrent INSERT race
-- conditions (chain forks). This down migration exists for completeness;
-- there is no operational reason to apply it.

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

CREATE OR REPLACE FUNCTION compute_endpoint_hash()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash_val VARCHAR(64);
BEGIN
    SELECT row_hash INTO prev_hash_val
    FROM endpoint_events
    ORDER BY id DESC LIMIT 1;

    IF prev_hash_val IS NULL THEN
        prev_hash_val := '0000000000000000000000000000000000000000000000000000000000000000';
    END IF;

    NEW.prev_hash := prev_hash_val;
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
