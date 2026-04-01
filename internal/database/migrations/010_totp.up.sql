-- Two-Factor Authentication (TOTP) support
ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT false;

-- Recovery codes (one-time use, 8 codes generated on setup)
CREATE TABLE totp_recovery_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(20) NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_recovery_codes_user ON totp_recovery_codes(user_id);
