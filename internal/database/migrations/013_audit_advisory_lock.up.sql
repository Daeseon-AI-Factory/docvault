-- Hash chain advisory lock (fixes L-SEC-3 in docs/LIMITATIONS.md).
--
-- The 008_log_integrity triggers compute prev_hash by reading the most
-- recent row's row_hash via SELECT ... ORDER BY id DESC LIMIT 1. Without
-- serialization, two concurrent INSERTs can read the same prev_hash and
-- produce a fork in the chain.
--
-- pg_advisory_xact_lock(int8) takes a transaction-scoped lock identified
-- by a stable int64 key (hashtext returns int4, sign-extended). The lock
-- is released automatically at COMMIT/ROLLBACK. Concurrent INSERTs that
-- try to take the same key block until the prior transaction completes.
--
-- Trade-off: hash chain inserts become serialized per table. At the
-- intended scale (~50K events/day) this is well under any throughput
-- limit. Above ~10 inserts/second sustained, consider batching or a
-- different integrity strategy.

CREATE OR REPLACE FUNCTION compute_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash_val VARCHAR(64);
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit_logs_chain'));

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
    PERFORM pg_advisory_xact_lock(hashtext('endpoint_events_chain'));

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
