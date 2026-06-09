package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	db       *pgxpool.Pool
	jwt      *JWTService
	logger   *slog.Logger
	auditLog AuditLogFunc
}

type AuditLogFunc func(ctx context.Context, userID int64, action string, statusCode int, r *http.Request)

func NewHandler(db *pgxpool.Pool, jwt *JWTService, logger *slog.Logger, auditLog ...AuditLogFunc) *Handler {
	h := &Handler{db: db, jwt: jwt, logger: logger}
	if len(auditLog) > 0 {
		h.auditLog = auditLog[0]
	}
	return h
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	User         loginUser `json:"user"`
}

type loginUser struct {
	ID       int64     `json:"id"`
	Username string    `json:"username"`
	FullName string    `json:"full_name"`
	Role     user.Role `json:"role"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password are required"}`, http.StatusBadRequest)
		return
	}

	u, err := h.findUserByUsername(r.Context(), req.Username)
	if err != nil {
		h.logger.Error("login: find user", "error", err, "username", req.Username)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if !u.IsActive {
		h.logAudit(r, u.ID, "login", http.StatusForbidden)
		http.Error(w, `{"error":"account is disabled"}`, http.StatusForbidden)
		return
	}

	if err := user.CheckPassword(u.PasswordHash, req.Password); err != nil {
		h.logAudit(r, u.ID, "login", http.StatusUnauthorized)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	tokens, err := h.jwt.GenerateTokenPair(u)
	if err != nil {
		h.logAudit(r, u.ID, "login", http.StatusInternalServerError)
		h.logger.Error("login: generate tokens", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	resp := loginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User: loginUser{
			ID:       u.ID,
			Username: u.Username,
			FullName: u.FullName,
			Role:     u.Role,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	h.logAudit(r, u.ID, "login", http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) logAudit(r *http.Request, userID int64, action string, statusCode int) {
	if h.auditLog == nil {
		return
	}
	h.auditLog(r.Context(), userID, action, statusCode, r)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	claims, err := h.jwt.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, `{"error":"invalid refresh token"}`, http.StatusUnauthorized)
		return
	}

	u, err := h.findUserByID(r.Context(), claims.UserID)
	if err != nil {
		h.logger.Error("refresh: find user", "error", err)
		http.Error(w, `{"error":"user not found"}`, http.StatusUnauthorized)
		return
	}

	if !u.IsActive {
		http.Error(w, `{"error":"account is disabled"}`, http.StatusForbidden)
		return
	}

	tokens, err := h.jwt.GenerateTokenPair(u)
	if err != nil {
		h.logger.Error("refresh: generate tokens", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (h *Handler) findUserByUsername(ctx context.Context, username string) (*user.User, error) {
	var u user.User
	err := h.db.QueryRow(ctx,
		`SELECT id, username, email, password_hash, full_name, role, department, is_active, created_at, updated_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("find user by username %s: %w", username, err)
	}
	return &u, nil
}

func (h *Handler) findUserByID(ctx context.Context, id int64) (*user.User, error) {
	var u user.User
	err := h.db.QueryRow(ctx,
		`SELECT id, username, email, password_hash, full_name, role, department, is_active, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("find user by id %d: %w", id, err)
	}
	return &u, nil
}
