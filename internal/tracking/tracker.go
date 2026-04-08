package tracking

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TrackedFile represents a file registered for hash-based tracking.
type TrackedFile struct {
	ID           int64     `json:"id"`
	OriginalName string    `json:"original_name"`
	SHA256Hash   string    `json:"sha256_hash"`
	MD5Hash      string    `json:"md5_hash"`
	Sensitivity  string    `json:"sensitivity"`
	Description  string    `json:"description"`
	RegisteredBy *int64    `json:"registered_by"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}

// Detection records when a tracked file was found on an endpoint.
type Detection struct {
	ID            int64     `json:"id"`
	TrackedFileID int64     `json:"tracked_file_id"`
	UserID        *int64    `json:"user_id"`
	Hostname      string    `json:"hostname"`
	FoundPath     string    `json:"found_path"`
	FoundName     string    `json:"found_name"`
	EventType     string    `json:"event_type"`
	ProcessName   string    `json:"process_name"`
	DetectedAt    time.Time `json:"detected_at"`
	// Joined fields
	OriginalName string `json:"original_name,omitempty"`
	Sensitivity  string `json:"sensitivity,omitempty"`
}

// Tracker matches incoming file events against registered file hashes.
type Tracker struct {
	db     *pgxpool.Pool
	logger *slog.Logger
	// In-memory cache of tracked hashes for fast lookup
	sha256Set map[string]int64 // sha256 -> tracked_file_id
	md5Set    map[string]int64 // md5 -> tracked_file_id
}

func NewTracker(db *pgxpool.Pool, logger *slog.Logger) *Tracker {
	t := &Tracker{
		db:        db,
		logger:    logger,
		sha256Set: make(map[string]int64),
		md5Set:    make(map[string]int64),
	}
	t.RefreshCache(context.Background())
	return t
}

// RefreshCache reloads tracked file hashes from DB into memory.
func (t *Tracker) RefreshCache(ctx context.Context) {
	rows, err := t.db.Query(ctx,
		`SELECT id, sha256_hash, md5_hash FROM tracked_files WHERE is_active = true`)
	if err != nil {
		t.logger.Error("refresh tracked files cache", "error", err)
		return
	}
	defer rows.Close()

	sha256Set := make(map[string]int64)
	md5Set := make(map[string]int64)

	for rows.Next() {
		var id int64
		var sha256, md5 string
		if err := rows.Scan(&id, &sha256, &md5); err == nil {
			if sha256 != "" {
				sha256Set[sha256] = id
			}
			if md5 != "" {
				md5Set[md5] = id
			}
		}
	}

	t.sha256Set = sha256Set
	t.md5Set = md5Set
	t.logger.Info("tracked files cache refreshed", "count", len(sha256Set))
}

// CheckEvent checks if an event's file hash matches any tracked file.
// Returns the tracked file ID if matched, 0 otherwise.
func (t *Tracker) CheckEvent(ctx context.Context, sha256, md5, hostname, foundPath, foundName, eventType, processName string, userID *int64) int64 {
	var matchedID int64

	if sha256 != "" {
		if id, ok := t.sha256Set[sha256]; ok {
			matchedID = id
		}
	}
	if matchedID == 0 && md5 != "" {
		if id, ok := t.md5Set[md5]; ok {
			matchedID = id
		}
	}

	if matchedID == 0 {
		return 0
	}

	// Record detection
	_, err := t.db.Exec(ctx,
		`INSERT INTO tracked_file_detections
		 (tracked_file_id, user_id, hostname, found_path, found_name, event_type, process_name)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		matchedID, userID, hostname, foundPath, foundName, eventType, processName)
	if err != nil {
		t.logger.Error("record tracked file detection", "error", err)
	}

	t.logger.Warn("TRACKED FILE DETECTED",
		"tracked_file_id", matchedID,
		"found_as", foundName,
		"hostname", hostname,
		"event_type", eventType,
	)

	return matchedID
}

// --- CRUD ---

func (t *Tracker) Register(ctx context.Context, name, sha256, md5, sensitivity, description string, userID int64) error {
	_, err := t.db.Exec(ctx,
		`INSERT INTO tracked_files (original_name, sha256_hash, md5_hash, sensitivity, description, registered_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (sha256_hash) DO UPDATE SET original_name = $1, sensitivity = $4, description = $5, is_active = true`,
		name, sha256, md5, sensitivity, description, userID)
	if err != nil {
		return fmt.Errorf("register tracked file: %w", err)
	}
	t.RefreshCache(ctx)
	return nil
}

func (t *Tracker) Unregister(ctx context.Context, id int64) error {
	_, err := t.db.Exec(ctx, `UPDATE tracked_files SET is_active = false WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("unregister tracked file: %w", err)
	}
	t.RefreshCache(ctx)
	return nil
}

func (t *Tracker) List(ctx context.Context) ([]TrackedFile, error) {
	rows, err := t.db.Query(ctx,
		`SELECT id, original_name, sha256_hash, md5_hash, sensitivity, description,
		        registered_by, is_active, created_at
		 FROM tracked_files ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tracked files: %w", err)
	}
	defer rows.Close()

	var files []TrackedFile
	for rows.Next() {
		var f TrackedFile
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.SHA256Hash, &f.MD5Hash,
			&f.Sensitivity, &f.Description, &f.RegisteredBy, &f.IsActive, &f.CreatedAt); err == nil {
			files = append(files, f)
		}
	}
	return files, nil
}

func (t *Tracker) GetDetections(ctx context.Context, trackedFileID int64, limit int) ([]Detection, error) {
	rows, err := t.db.Query(ctx,
		`SELECT d.id, d.tracked_file_id, d.user_id, d.hostname, d.found_path, d.found_name,
		        d.event_type, d.process_name, d.detected_at, tf.original_name, tf.sensitivity
		 FROM tracked_file_detections d
		 JOIN tracked_files tf ON d.tracked_file_id = tf.id
		 WHERE d.tracked_file_id = $1
		 ORDER BY d.detected_at DESC LIMIT $2`, trackedFileID, limit)
	if err != nil {
		return nil, fmt.Errorf("get detections: %w", err)
	}
	defer rows.Close()

	var dets []Detection
	for rows.Next() {
		var d Detection
		if err := rows.Scan(&d.ID, &d.TrackedFileID, &d.UserID, &d.Hostname, &d.FoundPath,
			&d.FoundName, &d.EventType, &d.ProcessName, &d.DetectedAt,
			&d.OriginalName, &d.Sensitivity); err == nil {
			dets = append(dets, d)
		}
	}
	return dets, nil
}

func (t *Tracker) GetAllDetections(ctx context.Context, limit int) ([]Detection, error) {
	rows, err := t.db.Query(ctx,
		`SELECT d.id, d.tracked_file_id, d.user_id, d.hostname, d.found_path, d.found_name,
		        d.event_type, d.process_name, d.detected_at, tf.original_name, tf.sensitivity
		 FROM tracked_file_detections d
		 JOIN tracked_files tf ON d.tracked_file_id = tf.id
		 ORDER BY d.detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("get all detections: %w", err)
	}
	defer rows.Close()

	var dets []Detection
	for rows.Next() {
		var d Detection
		if err := rows.Scan(&d.ID, &d.TrackedFileID, &d.UserID, &d.Hostname, &d.FoundPath,
			&d.FoundName, &d.EventType, &d.ProcessName, &d.DetectedAt,
			&d.OriginalName, &d.Sensitivity); err == nil {
			dets = append(dets, d)
		}
	}
	return dets, nil
}
