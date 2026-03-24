package folder

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

func (r *Repository) Create(ctx context.Context, f *Folder) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO folders (name, parent_id, created_by)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at, updated_at`,
		f.Name, f.ParentID, f.CreatedBy,
	).Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert folder: %w", err)
	}
	return nil
}

func (r *Repository) GetByID(ctx context.Context, id int64) (*Folder, error) {
	var f Folder
	err := r.db.QueryRow(ctx,
		`SELECT id, name, parent_id, created_by, is_deleted, created_at, updated_at
		 FROM folders WHERE id = $1 AND is_deleted = false`, id,
	).Scan(&f.ID, &f.Name, &f.ParentID, &f.CreatedBy, &f.IsDeleted, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get folder %d: %w", id, err)
	}
	return &f, nil
}

func (r *Repository) ListChildren(ctx context.Context, parentID *int64) ([]*Folder, error) {
	var query string
	var args []interface{}

	if parentID == nil {
		query = `SELECT id, name, parent_id, created_by, is_deleted, created_at, updated_at
		         FROM folders WHERE parent_id IS NULL AND is_deleted = false ORDER BY name`
	} else {
		query = `SELECT id, name, parent_id, created_by, is_deleted, created_at, updated_at
		         FROM folders WHERE parent_id = $1 AND is_deleted = false ORDER BY name`
		args = append(args, *parentID)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list child folders: %w", err)
	}
	defer rows.Close()

	var folders []*Folder
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.Name, &f.ParentID, &f.CreatedBy, &f.IsDeleted, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan folder: %w", err)
		}
		folders = append(folders, &f)
	}
	return folders, rows.Err()
}

func (r *Repository) Update(ctx context.Context, id int64, name string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE folders SET name = $1, updated_at = NOW() WHERE id = $2 AND is_deleted = false`,
		name, id,
	)
	if err != nil {
		return fmt.Errorf("update folder %d: %w", id, err)
	}
	return nil
}

func (r *Repository) SoftDelete(ctx context.Context, id int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE folders SET is_deleted = true, updated_at = NOW() WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("soft delete folder %d: %w", id, err)
	}
	return nil
}

// Permission operations

func (r *Repository) SetPermission(ctx context.Context, fp *FolderPermission) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO folder_permissions (folder_id, user_id, permission, granted_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (folder_id, user_id) DO UPDATE SET permission = $3, granted_by = $4
		 RETURNING id, created_at`,
		fp.FolderID, fp.UserID, fp.Permission, fp.GrantedBy,
	).Scan(&fp.ID, &fp.CreatedAt)
	if err != nil {
		return fmt.Errorf("set folder permission: %w", err)
	}
	return nil
}

func (r *Repository) GetPermission(ctx context.Context, folderID, userID int64) (*FolderPermission, error) {
	var fp FolderPermission
	err := r.db.QueryRow(ctx,
		`SELECT id, folder_id, user_id, permission, granted_by, created_at
		 FROM folder_permissions WHERE folder_id = $1 AND user_id = $2`,
		folderID, userID,
	).Scan(&fp.ID, &fp.FolderID, &fp.UserID, &fp.Permission, &fp.GrantedBy, &fp.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get permission for folder %d user %d: %w", folderID, userID, err)
	}
	return &fp, nil
}

func (r *Repository) ListPermissions(ctx context.Context, folderID int64) ([]*FolderPermission, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, folder_id, user_id, permission, granted_by, created_at
		 FROM folder_permissions WHERE folder_id = $1 ORDER BY user_id`, folderID,
	)
	if err != nil {
		return nil, fmt.Errorf("list permissions for folder %d: %w", folderID, err)
	}
	defer rows.Close()

	var perms []*FolderPermission
	for rows.Next() {
		var fp FolderPermission
		if err := rows.Scan(&fp.ID, &fp.FolderID, &fp.UserID, &fp.Permission, &fp.GrantedBy, &fp.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, &fp)
	}
	return perms, rows.Err()
}

func (r *Repository) RemovePermission(ctx context.Context, folderID, userID int64) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM folder_permissions WHERE folder_id = $1 AND user_id = $2`,
		folderID, userID,
	)
	if err != nil {
		return fmt.Errorf("remove permission for folder %d user %d: %w", folderID, userID, err)
	}
	return nil
}

// CheckAccess checks if a user has at least the required permission level on a folder.
// Permission hierarchy: admin > write > read
func (r *Repository) CheckAccess(ctx context.Context, folderID, userID int64, required Permission) (bool, error) {
	fp, err := r.GetPermission(ctx, folderID, userID)
	if err != nil {
		return false, nil // no permission = no access
	}

	hierarchy := map[Permission]int{
		PermRead:  1,
		PermWrite: 2,
		PermAdmin: 3,
	}

	return hierarchy[fp.Permission] >= hierarchy[required], nil
}
