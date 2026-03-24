package user

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, u *User) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, full_name, role, department)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, is_active, created_at, updated_at`,
		u.Username, u.Email, u.PasswordHash, u.FullName, u.Role, u.Department,
	).Scan(&u.ID, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *Repository) GetByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := r.db.QueryRow(ctx,
		`SELECT id, username, email, password_hash, full_name, role, department, is_active, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get user %d: %w", id, err)
	}
	return &u, nil
}

func (r *Repository) List(ctx context.Context) ([]*User, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, username, email, password_hash, full_name, role, department, is_active, created_at, updated_at
		 FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, &u)
	}
	return users, rows.Err()
}

func (r *Repository) Update(ctx context.Context, u *User) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET email = $1, full_name = $2, role = $3, department = $4, is_active = $5, updated_at = NOW()
		 WHERE id = $6`,
		u.Email, u.FullName, u.Role, u.Department, u.IsActive, u.ID,
	)
	if err != nil {
		return fmt.Errorf("update user %d: %w", u.ID, err)
	}
	return nil
}

func (r *Repository) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("update password for user %d: %w", id, err)
	}
	return nil
}
