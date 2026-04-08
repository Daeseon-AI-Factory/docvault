-- Tracked files: mark specific files for hash-based tracking
-- Even if renamed, moved, or extension changed, the content hash matches.
CREATE TABLE tracked_files (
    id SERIAL PRIMARY KEY,
    original_name VARCHAR(500) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    md5_hash VARCHAR(32) NOT NULL DEFAULT '',
    sensitivity VARCHAR(20) NOT NULL DEFAULT 'confidential',
    description TEXT NOT NULL DEFAULT '',
    registered_by INTEGER REFERENCES users(id),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(sha256_hash)
);
CREATE INDEX idx_tracked_files_sha256 ON tracked_files(sha256_hash);
CREATE INDEX idx_tracked_files_md5 ON tracked_files(md5_hash) WHERE md5_hash != '';

-- Detection log: when a tracked file is detected anywhere
CREATE TABLE tracked_file_detections (
    id SERIAL PRIMARY KEY,
    tracked_file_id INTEGER NOT NULL REFERENCES tracked_files(id),
    user_id INTEGER REFERENCES users(id),
    hostname VARCHAR(255) NOT NULL DEFAULT '',
    found_path VARCHAR(1000) NOT NULL,
    found_name VARCHAR(500) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    process_name VARCHAR(255) NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tracked_detections_file ON tracked_file_detections(tracked_file_id);
CREATE INDEX idx_tracked_detections_time ON tracked_file_detections(detected_at DESC);
