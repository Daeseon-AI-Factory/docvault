CREATE TABLE encryption_keys (
    id BIGSERIAL PRIMARY KEY,
    key_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    encrypted_key BYTEA NOT NULL,
    algorithm VARCHAR(20) NOT NULL DEFAULT 'AES-256-GCM',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

CREATE INDEX idx_encryption_keys_key_id ON encryption_keys(key_id);
