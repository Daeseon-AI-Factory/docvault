package monitoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds all monitoring configuration loaded from the database.
// It is cached in memory and refreshed periodically.
type Config struct {
	ProcessGroups map[string][]ProcessEntry // group_name -> processes
	Extensions    []ExtensionEntry
	Paths         []PathEntry
	DisguiseRules []DisguiseEntry

	// Derived lookup maps (built from DB data)
	processLookup map[string]string // lowercase process_name -> group_name
	sensitiveExts map[string]bool   // extension -> is_sensitive
	extCategories map[string]string // extension -> category
	disguiseSet   map[string]bool   // "category|.ext" -> true
}

type ProcessEntry struct {
	GroupName   string `json:"group_name"`
	ProcessName string `json:"process_name"`
	DisplayName string `json:"display_name"`
}

type ExtensionEntry struct {
	Category    string `json:"category"`
	Extension   string `json:"extension"`
	DisplayName string `json:"display_name"`
	IsSensitive bool   `json:"is_sensitive"`
}

type PathEntry struct {
	PathType    string `json:"path_type"`
	PathPattern string `json:"path_pattern"`
	Description string `json:"description"`
}

type DisguiseEntry struct {
	FromCategory string `json:"from_category"`
	ToExtension  string `json:"to_extension"`
}

// Repository loads and caches monitoring configuration from the database.
type Repository struct {
	db    *pgxpool.Pool
	mu    sync.RWMutex
	cache *Config
	lastLoad time.Time
	ttl   time.Duration
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db:  db,
		ttl: 5 * time.Minute, // refresh every 5 minutes
	}
}

// Get returns the cached config, reloading from DB if stale.
func (r *Repository) Get(ctx context.Context) (*Config, error) {
	r.mu.RLock()
	if r.cache != nil && time.Since(r.lastLoad) < r.ttl {
		defer r.mu.RUnlock()
		return r.cache, nil
	}
	r.mu.RUnlock()

	return r.Reload(ctx)
}

// Reload forces a fresh load from the database.
func (r *Repository) Reload(ctx context.Context) (*Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg := &Config{
		ProcessGroups: make(map[string][]ProcessEntry),
		processLookup: make(map[string]string),
		sensitiveExts: make(map[string]bool),
		extCategories: make(map[string]string),
		disguiseSet:   make(map[string]bool),
	}

	// Load process groups
	rows, err := r.db.Query(ctx,
		`SELECT group_name, process_name, display_name FROM monitoring_process_groups WHERE is_active = true ORDER BY group_name, process_name`)
	if err != nil {
		return nil, fmt.Errorf("load process groups: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e ProcessEntry
		if err := rows.Scan(&e.GroupName, &e.ProcessName, &e.DisplayName); err != nil {
			return nil, fmt.Errorf("scan process group: %w", err)
		}
		cfg.ProcessGroups[e.GroupName] = append(cfg.ProcessGroups[e.GroupName], e)
		cfg.processLookup[strings.ToLower(e.ProcessName)] = e.GroupName
	}
	rows.Close()

	// Load extensions
	rows2, err := r.db.Query(ctx,
		`SELECT category, extension, display_name, is_sensitive FROM monitoring_extensions WHERE is_active = true ORDER BY category, extension`)
	if err != nil {
		return nil, fmt.Errorf("load extensions: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var e ExtensionEntry
		if err := rows2.Scan(&e.Category, &e.Extension, &e.DisplayName, &e.IsSensitive); err != nil {
			return nil, fmt.Errorf("scan extension: %w", err)
		}
		cfg.Extensions = append(cfg.Extensions, e)
		cfg.sensitiveExts[strings.ToLower(e.Extension)] = e.IsSensitive
		cfg.extCategories[strings.ToLower(e.Extension)] = e.Category
	}
	rows2.Close()

	// Load paths
	rows3, err := r.db.Query(ctx,
		`SELECT path_type, path_pattern, description FROM monitoring_paths WHERE is_active = true ORDER BY path_type`)
	if err != nil {
		return nil, fmt.Errorf("load paths: %w", err)
	}
	defer rows3.Close()

	for rows3.Next() {
		var e PathEntry
		if err := rows3.Scan(&e.PathType, &e.PathPattern, &e.Description); err != nil {
			return nil, fmt.Errorf("scan path: %w", err)
		}
		cfg.Paths = append(cfg.Paths, e)
	}
	rows3.Close()

	// Load disguise rules
	rows4, err := r.db.Query(ctx,
		`SELECT from_category, to_extension FROM monitoring_ext_disguise WHERE is_active = true`)
	if err != nil {
		return nil, fmt.Errorf("load disguise rules: %w", err)
	}
	defer rows4.Close()

	for rows4.Next() {
		var e DisguiseEntry
		if err := rows4.Scan(&e.FromCategory, &e.ToExtension); err != nil {
			return nil, fmt.Errorf("scan disguise: %w", err)
		}
		cfg.DisguiseRules = append(cfg.DisguiseRules, e)
		cfg.disguiseSet[e.FromCategory+"|"+strings.ToLower(e.ToExtension)] = true
	}
	rows4.Close()

	r.cache = cfg
	r.lastLoad = time.Now()

	return cfg, nil
}

// IsInProcessGroup checks if a process belongs to the specified group.
func (c *Config) IsInProcessGroup(group, processName string) bool {
	g, ok := c.processLookup[strings.ToLower(processName)]
	return ok && g == group
}

// GetProcessGroup returns the group name for a process, or "" if unknown.
func (c *Config) GetProcessGroup(processName string) string {
	return c.processLookup[strings.ToLower(processName)]
}

// GetProcessDisplayName returns a human-readable name for a process.
func (c *Config) GetProcessDisplayName(processName string) string {
	pLower := strings.ToLower(processName)
	for _, entries := range c.ProcessGroups {
		for _, e := range entries {
			if strings.ToLower(e.ProcessName) == pLower {
				return e.DisplayName
			}
		}
	}
	return processName
}

// IsSensitiveExtension returns true if the extension is marked as sensitive.
func (c *Config) IsSensitiveExtension(ext string) bool {
	return c.sensitiveExts[strings.ToLower(ext)]
}

// GetExtensionCategory returns the category for an extension (e.g., "cad", "document").
func (c *Config) GetExtensionCategory(ext string) string {
	return c.extCategories[strings.ToLower(ext)]
}

// IsDisguise checks if renaming from one extension to another is a disguise.
func (c *Config) IsDisguise(oldExt, newExt string) bool {
	oldCategory := c.GetExtensionCategory(strings.ToLower(oldExt))
	if oldCategory == "" {
		return false
	}
	return c.disguiseSet[oldCategory+"|"+strings.ToLower(newExt)]
}

// SensitiveExtensionsList returns all sensitive extensions as a slice for SQL queries.
func (c *Config) SensitiveExtensionsList() []string {
	var exts []string
	for ext, sensitive := range c.sensitiveExts {
		if sensitive {
			exts = append(exts, ext)
		}
	}
	return exts
}

// ProcessNamesForGroup returns all process names for a given group.
func (c *Config) ProcessNamesForGroup(group string) []string {
	entries := c.ProcessGroups[group]
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.ProcessName)
	}
	return names
}

// PathsForType returns all path patterns for a given type.
func (c *Config) PathsForType(pathType string) []string {
	var paths []string
	for _, p := range c.Paths {
		if p.PathType == pathType {
			paths = append(paths, p.PathPattern)
		}
	}
	return paths
}
