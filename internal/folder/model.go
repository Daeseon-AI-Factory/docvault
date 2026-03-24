package folder

import "time"

type Folder struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	ParentID  *int64    `json:"parent_id,omitempty"`
	CreatedBy int64     `json:"created_by"`
	IsDeleted bool      `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
	PermAdmin Permission = "admin"
)

type FolderPermission struct {
	ID         int64      `json:"id"`
	FolderID   int64      `json:"folder_id"`
	UserID     int64      `json:"user_id"`
	Permission Permission `json:"permission"`
	GrantedBy  int64      `json:"granted_by"`
	CreatedAt  time.Time  `json:"created_at"`
}
