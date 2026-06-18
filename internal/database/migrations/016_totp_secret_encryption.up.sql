-- Encrypted TOTP seeds include an enc:v1 prefix, nonce, and GCM tag, so they
-- no longer fit reliably in the original VARCHAR(64) plaintext column.
ALTER TABLE users ALTER COLUMN totp_secret TYPE TEXT;
