package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeriveAction(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Action
	}{
		// Auth
		{"POST", "/api/auth/login", ActionLogin},
		{"GET", "/logout", ActionLogout},

		// Files
		{"POST", "/api/files/upload", ActionFileUpload},
		{"POST", "/files/upload", ActionFileUpload},
		{"GET", "/api/files/42/download", ActionFileDownload},
		{"DELETE", "/api/files/42", ActionFileDelete},
		{"POST", "/api/files/42/checkout", ActionFileCheckout},
		{"POST", "/files/42/checkout", ActionFileCheckout},
		{"POST", "/api/files/42/checkin", ActionFileCheckin},
		{"POST", "/files/42/checkin", ActionFileCheckin},

		// Folders
		{"POST", "/api/folders", ActionFolderCreate},
		{"POST", "/folders/create", ActionFolderCreate},
		{"PUT", "/api/folders/5", ActionFolderUpdate},
		{"DELETE", "/api/folders/5", ActionFolderDelete},

		// Folder permissions
		{"POST", "/api/folders/5/permissions", ActionPermissionSet},
		{"DELETE", "/api/folders/5/permissions/3", ActionPermissionDel},

		// Users
		{"POST", "/api/admin/users", ActionUserCreate},
		{"POST", "/api/admin/users/", ActionUserCreate},
		{"POST", "/admin/users/create", ActionUserCreate},
		{"PUT", "/api/admin/users/7", ActionUserUpdate},
		{"POST", "/admin/users/7/edit", ActionUserUpdate},
		{"POST", "/api/admin/users/7/reset-password", ActionUserResetPwd},
		{"POST", "/admin/users/7/reset-password", ActionUserResetPwd},

		// Admin web forms
		{"POST", "/admin/alerts/rules/create", ActionAlertRuleCreate},
		{"POST", "/admin/alerts/9/acknowledge", ActionAlertAck},
		{"POST", "/admin/monitoring/processes/add", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/processes/2/delete", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/processes/2/toggle", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/extensions/add", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/extensions/2/delete", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/extensions/2/toggle", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/paths/add", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/paths/2/delete", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/disguise/add", ActionMonitoringConfigChange},
		{"POST", "/admin/monitoring/disguise/2/delete", ActionMonitoringConfigChange},
		{"POST", "/admin/tracking/add", ActionTrackingAdd},
		{"POST", "/admin/tracking/2/delete", ActionTrackingDelete},

		// Account security forms
		{"POST", "/account/2fa/setup", ActionTwoFactorSetup},
		{"POST", "/account/2fa/verify", ActionTwoFactorVerify},
		{"POST", "/account/2fa/disable", ActionTwoFactorDisable},

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
		ActionLogin:                  false,
		ActionLogout:                 false,
		ActionFileUpload:             false,
		ActionFileDownload:           false,
		ActionFileDelete:             false,
		ActionFileCheckout:           false,
		ActionFileCheckin:            false,
		ActionFolderCreate:           false,
		ActionFolderUpdate:           false,
		ActionFolderDelete:           false,
		ActionPermissionSet:          false,
		ActionPermissionDel:          false,
		ActionUserCreate:             false,
		ActionUserUpdate:             false,
		ActionUserResetPwd:           false,
		ActionAlertAck:               false,
		ActionAlertRuleCreate:        false,
		ActionMonitoringConfigChange: false,
		ActionTrackingAdd:            false,
		ActionTrackingDelete:         false,
		ActionTwoFactorSetup:         false,
		ActionTwoFactorVerify:        false,
		ActionTwoFactorDisable:       false,
	}

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/auth/login"},
		{"GET", "/logout"},
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
		{"POST", "/admin/alerts/1/acknowledge"},
		{"POST", "/admin/alerts/rules/create"},
		{"POST", "/admin/monitoring/processes/1/delete"},
		{"POST", "/admin/tracking/add"},
		{"POST", "/admin/tracking/1/delete"},
		{"POST", "/account/2fa/setup"},
		{"POST", "/account/2fa/verify"},
		{"POST", "/account/2fa/disable"},
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

func TestStatusRecorderPreservesFlusherWhenUnderlyingSupportsIt(t *testing.T) {
	rec := httptest.NewRecorder()
	status := &statusRecorder{ResponseWriter: rec, status: http.StatusOK}
	wrapped := &flushStatusRecorder{statusRecorder: status}

	if _, ok := interface{}(wrapped).(http.Flusher); !ok {
		t.Fatal("wrapped recorder should implement http.Flusher")
	}

	wrapped.WriteHeader(http.StatusAccepted)
	wrapped.Flush()

	if status.status != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", status.status, http.StatusAccepted)
	}
	if !rec.Flushed {
		t.Fatal("underlying recorder was not flushed")
	}
}
