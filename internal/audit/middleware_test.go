package audit

import "testing"

func TestDeriveAction(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Action
	}{
		// Auth
		{"POST", "/api/auth/login", ActionLogin},

		// Files
		{"POST", "/api/files/upload", ActionFileUpload},
		{"GET", "/api/files/42/download", ActionFileDownload},
		{"DELETE", "/api/files/42", ActionFileDelete},
		{"POST", "/api/files/42/checkout", ActionFileCheckout},
		{"POST", "/api/files/42/checkin", ActionFileCheckin},

		// Folders
		{"POST", "/api/folders", ActionFolderCreate},
		{"PUT", "/api/folders/5", ActionFolderUpdate},
		{"DELETE", "/api/folders/5", ActionFolderDelete},

		// Folder permissions
		{"POST", "/api/folders/5/permissions", ActionPermissionSet},
		{"DELETE", "/api/folders/5/permissions/3", ActionPermissionDel},

		// Users
		{"POST", "/api/admin/users", ActionUserCreate},
		{"POST", "/api/admin/users/", ActionUserCreate},
		{"PUT", "/api/admin/users/7", ActionUserUpdate},
		{"POST", "/api/admin/users/7/reset-password", ActionUserResetPwd},

		// Non-auditable
		{"GET", "/api/me", ""},
		{"GET", "/api/files", ""},
		{"GET", "/health", ""},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := deriveAction(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("deriveAction(%s, %s) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestDeriveActionCoversAllActions(t *testing.T) {
	// Every defined Action constant should be reachable from deriveAction
	allActions := map[Action]bool{
		ActionLogin:        false,
		ActionFileUpload:   false,
		ActionFileDownload: false,
		ActionFileDelete:   false,
		ActionFileCheckout: false,
		ActionFileCheckin:  false,
		ActionFolderCreate: false,
		ActionFolderUpdate: false,
		ActionFolderDelete: false,
		ActionPermissionSet: false,
		ActionPermissionDel: false,
		ActionUserCreate:   false,
		ActionUserUpdate:   false,
		ActionUserResetPwd: false,
	}

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/auth/login"},
		{"POST", "/api/files/upload"},
		{"GET", "/api/files/1/download"},
		{"DELETE", "/api/files/1"},
		{"POST", "/api/files/1/checkout"},
		{"POST", "/api/files/1/checkin"},
		{"POST", "/api/folders"},
		{"PUT", "/api/folders/1"},
		{"DELETE", "/api/folders/1"},
		{"POST", "/api/folders/1/permissions"},
		{"DELETE", "/api/folders/1/permissions/2"},
		{"POST", "/api/admin/users/"},
		{"PUT", "/api/admin/users/1"},
		{"POST", "/api/admin/users/1/reset-password"},
	}

	for _, r := range routes {
		action := deriveAction(r.method, r.path)
		if action != "" {
			allActions[action] = true
		}
	}

	for action, covered := range allActions {
		if !covered {
			t.Errorf("Action %q is never produced by deriveAction — dead code or missing route", action)
		}
	}
}
