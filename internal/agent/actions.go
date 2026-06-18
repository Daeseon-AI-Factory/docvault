package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func randomPW() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// logAction records a mutating action with the state needed to undo it.
func logAction(ctx context.Context, db *pgxpool.Pool, actionType string, targetID int64, summary string, prev map[string]any) (int64, error) {
	var ps []byte
	if prev != nil {
		ps, _ = json.Marshal(prev)
	}
	var id int64
	err := db.QueryRow(ctx,
		`INSERT INTO agent_actions (action_type, target_id, summary, prev_state, performed_by)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		actionType, targetID, summary, ps, nullableInt(actorFromContext(ctx)),
	).Scan(&id)
	return id, err
}

// actionTools are mutating tools. Every action is logged to agent_actions so it
// can be rolled back. Only an admin (router-enforced) reaches these.
func actionTools() []Tool {
	return []Tool{
		{
			Name:                 "create_user",
			Description:          "새 사용자(직원)를 생성한다. username 필수. 임의 비밀번호로 생성되며 롤백(삭제) 가능. 서버가 실행 전 관리자 확인을 요구한다.",
			RequiresConfirmation: true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"username":   map[string]any{"type": "string"},
					"full_name":  map[string]any{"type": "string"},
					"email":      map[string]any{"type": "string"},
					"department": map[string]any{"type": "string"},
					"role":       map[string]any{"type": "string", "enum": []string{"employee", "manager", "admin"}},
				},
				"required": []string{"username"},
			},
			Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
				un := argStr(args, "username")
				if un == "" {
					return "", fmt.Errorf("username이 필요합니다")
				}
				role := strings.ToLower(argStr(args, "role"))
				if role != "admin" && role != "manager" && role != "employee" {
					role = "employee"
				}
				email := argStr(args, "email")
				if email == "" {
					email = un + "@company.local"
				}
				hash, err := user.HashPassword(randomPW())
				if err != nil {
					return "", err
				}
				var id int64
				err = db.QueryRow(ctx,
					`INSERT INTO users (username, email, password_hash, full_name, role, department)
					 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
					un, email, hash, argStr(args, "full_name"), role, argStr(args, "department"),
				).Scan(&id)
				if err != nil {
					return fmt.Sprintf(`{"error":"사용자 생성 실패(중복 username 등): %s"}`, err.Error()), nil
				}
				aid, _ := logAction(ctx, db, "create_user", id, fmt.Sprintf("사용자 생성: %s (%s)", un, role), nil)
				return fmt.Sprintf(`{"ok":true,"user_id":%d,"username":%q,"action_id":%d,"note":"임의 비밀번호로 생성됨. 롤백하면 삭제됩니다."}`, id, un, aid), nil
			},
		},
		{
			Name:                 "assign_host",
			Description:          "PC(호스트)를 직원에게 배정한다. 그 호스트의 과거/미래 이벤트가 해당 직원에게 귀속된다. 롤백 가능. 서버가 실행 전 관리자 확인을 요구한다.",
			RequiresConfirmation: true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"hostname": map[string]any{"type": "string"},
					"username": map[string]any{"type": "string"},
				},
				"required": []string{"hostname", "username"},
			},
			Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
				hostname := argStr(args, "hostname")
				username := argStr(args, "username")
				if hostname == "" || username == "" {
					return "", fmt.Errorf("hostname과 username이 필요합니다")
				}
				rows, err := db.Query(ctx, `SELECT id, user_id FROM endpoint_agents WHERE hostname=$1 ORDER BY id`, hostname)
				if err != nil {
					return "", err
				}
				defer rows.Close()
				var agentIDs []int64
				prevAgents := []map[string]any{}
				for rows.Next() {
					var id int64
					var prevUser *int64
					if err := rows.Scan(&id, &prevUser); err != nil {
						return "", err
					}
					agentIDs = append(agentIDs, id)
					prev := map[string]any{"agent_id": id, "prev_user_id": int64(0)}
					if prevUser != nil {
						prev["prev_user_id"] = *prevUser
					}
					prevAgents = append(prevAgents, prev)
				}
				if err := rows.Err(); err != nil {
					return "", err
				}
				if len(agentIDs) == 0 {
					return fmt.Sprintf(`{"error":"호스트를 찾을 수 없음: %s"}`, hostname), nil
				}
				var newUser int64
				if err := db.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, username).Scan(&newUser); err != nil {
					return fmt.Sprintf(`{"error":"사용자를 찾을 수 없음: %s"}`, username), nil
				}
				if _, err := db.Exec(ctx, `UPDATE endpoint_agents SET user_id=$1 WHERE hostname=$2`, newUser, hostname); err != nil {
					return "", err
				}
				prev := map[string]any{"hostname": hostname, "agents": prevAgents}
				aid, _ := logAction(ctx, db, "assign_host", agentIDs[0], fmt.Sprintf("호스트 %s → %s 배정", hostname, username), prev)
				return fmt.Sprintf(`{"ok":true,"hostname":%q,"assigned_to":%q,"action_id":%d}`, hostname, username, aid), nil
			},
		},
		{
			Name:                 "acknowledge_alert",
			Description:          "경보(alert)를 확인 처리한다. 롤백하면 미확인 상태로 되돌린다. 서버가 실행 전 관리자 확인을 요구한다.",
			RequiresConfirmation: true,
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"alert_id": map[string]any{"type": "integer"}},
				"required":   []string{"alert_id"},
			},
			Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
				aidArg := argInt(args, "alert_id", 0)
				if aidArg == 0 {
					return "", fmt.Errorf("alert_id가 필요합니다")
				}
				var wasAcked bool
				if err := db.QueryRow(ctx, `SELECT is_acknowledged FROM alerts WHERE id=$1`, aidArg).Scan(&wasAcked); err != nil {
					return fmt.Sprintf(`{"error":"경보 #%d 없음"}`, aidArg), nil
				}
				if _, err := db.Exec(ctx, `UPDATE alerts SET is_acknowledged=true, acknowledged_by=$2, acknowledged_at=NOW() WHERE id=$1`,
					aidArg, nullableInt(actorFromContext(ctx))); err != nil {
					return "", err
				}
				logID, _ := logAction(ctx, db, "acknowledge_alert", int64(aidArg), fmt.Sprintf("경보 #%d 확인 처리", aidArg), map[string]any{"was_acknowledged": wasAcked})
				return fmt.Sprintf(`{"ok":true,"alert_id":%d,"action_id":%d}`, aidArg, logID), nil
			},
		},
	}
}

// Rollback undoes a recorded agent action.
func Rollback(ctx context.Context, db *pgxpool.Pool, actionID int64) error {
	var at string
	var target *int64
	var ps []byte
	var undone bool
	if err := db.QueryRow(ctx, `SELECT action_type, target_id, prev_state, undone FROM agent_actions WHERE id=$1`, actionID).Scan(&at, &target, &ps, &undone); err != nil {
		return fmt.Errorf("작업을 찾을 수 없음: %w", err)
	}
	if undone {
		return fmt.Errorf("이미 되돌린 작업입니다")
	}
	var prev map[string]any
	if ps != nil {
		_ = json.Unmarshal(ps, &prev)
	}

	switch at {
	case "create_user":
		if target != nil {
			if _, err := db.Exec(ctx, `DELETE FROM users WHERE id=$1`, *target); err != nil {
				// fall back to deactivation if the user is now referenced
				if _, e2 := db.Exec(ctx, `UPDATE users SET is_active=false WHERE id=$1`, *target); e2 != nil {
					return err
				}
			}
		}
	case "assign_host":
		restoredAgents := false
		if agents, ok := prev["agents"].([]any); ok {
			for _, raw := range agents {
				item, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				agentID, ok := item["agent_id"].(float64)
				if !ok || agentID == 0 {
					continue
				}
				var pid any = nil
				if v, ok := item["prev_user_id"].(float64); ok && v != 0 {
					pid = int64(v)
				}
				_, _ = db.Exec(ctx, `UPDATE endpoint_agents SET user_id=$1 WHERE id=$2`, pid, int64(agentID))
				restoredAgents = true
			}
		}
		var pid any = nil
		if v, ok := prev["prev_user_id"].(float64); ok && v != 0 {
			pid = int64(v)
		}
		if !restoredAgents && target != nil {
			_, _ = db.Exec(ctx, `UPDATE endpoint_agents SET user_id=$1 WHERE id=$2`, pid, *target)
		}
	case "acknowledge_alert":
		if target != nil {
			_, _ = db.Exec(ctx, `UPDATE alerts SET is_acknowledged=false, acknowledged_by=NULL, acknowledged_at=NULL WHERE id=$1`, *target)
		}
	default:
		return fmt.Errorf("되돌릴 수 없는 작업 유형: %s", at)
	}

	_, err := db.Exec(ctx, `UPDATE agent_actions SET undone=true, undone_at=NOW() WHERE id=$1`, actionID)
	return err
}

// --- HTTP: rollback + action history (admin-only via router) ---

func (h *Handler) Actions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := h.engine.db.Query(r.Context(),
		`SELECT a.id, a.action_type, a.summary, a.undone, a.created_at, COALESCE(u.username,'')
		 FROM agent_actions a LEFT JOIN users u ON u.id = a.performed_by
		 ORDER BY a.created_at DESC LIMIT 30`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID        int64     `json:"id"`
		Type      string    `json:"type"`
		Summary   string    `json:"summary"`
		Undone    bool      `json:"undone"`
		CreatedAt time.Time `json:"created_at"`
		By        string    `json:"by"`
	}
	var out []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.ID, &x.Type, &x.Summary, &x.Undone, &x.CreatedAt, &x.By); err == nil {
			out = append(out, x)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"actions": out})
}

func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		ActionID int64 `json:"action_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ActionID == 0 {
		// also accept form value
		if v := r.FormValue("action_id"); v != "" {
			req.ActionID, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if req.ActionID == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "action_id가 필요합니다"})
		return
	}
	if err := Rollback(r.Context(), h.engine.db, req.ActionID); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	h.logger.Info("agent action rolled back", "action_id", req.ActionID)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "rolled_back": req.ActionID})
}
