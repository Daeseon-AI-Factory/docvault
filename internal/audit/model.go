package audit

import (
	"encoding/json"
	"time"
)

type Action string

const (
	ActionLogin          Action = "login"
	ActionLogout         Action = "logout"
	ActionFileUpload     Action = "file.upload"
	ActionFileDownload   Action = "file.download"
	ActionFileDelete     Action = "file.delete"
	ActionFileCheckout   Action = "file.checkout"
	ActionFileCheckin    Action = "file.checkin"
	ActionFolderCreate   Action = "folder.create"
	ActionFolderUpdate   Action = "folder.update"
	ActionFolderDelete   Action = "folder.delete"
	ActionPermissionSet  Action = "permission.set"
	ActionPermissionDel  Action = "permission.delete"
	ActionUserCreate     Action = "user.create"
	ActionUserUpdate     Action = "user.update"
	ActionUserResetPwd   Action = "user.reset_password"
)

type AuditLog struct {
	ID         int64           `json:"id"`
	UserID     int64           `json:"user_id"`
	Action     Action          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   *int64          `json:"target_id,omitempty"`
	TargetName string          `json:"target_name"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	IPAddress  string          `json:"ip_address"`
	UserAgent  string          `json:"user_agent"`
	StatusCode int             `json:"status_code"`
	CreatedAt  time.Time       `json:"created_at"`
	PrevHash   string          `json:"prev_hash,omitempty"`
	RowHash    string          `json:"row_hash,omitempty"`
}

type Entry struct {
	UserID     int64
	Action     Action
	TargetType string
	TargetID   *int64
	TargetName string
	Detail     interface{}
	IPAddress  string
	UserAgent  string
	StatusCode int
}
