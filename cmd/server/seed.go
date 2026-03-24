package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

func seedAdmin(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	// Check if admin already exists
	var count int
	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE username = 'admin'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check admin user: %w", err)
	}
	if count > 0 {
		logger.Info("admin user already exists, skipping seed")
		return nil
	}

	hash, err := user.HashPassword("admin1234!")
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO users (username, email, password_hash, full_name, role, department)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		"admin", "admin@company.local", hash, "System Admin", "admin", "IT",
	)
	if err != nil {
		return fmt.Errorf("insert admin user: %w", err)
	}

	logger.Info("seeded admin user (username: admin, password: admin1234!)")
	return nil
}
