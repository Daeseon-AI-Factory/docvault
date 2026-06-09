package auth

import (
	"testing"
	"time"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

func TestJWTGenerateAndValidate(t *testing.T) {
	svc := NewJWTService("test-secret-key-for-jwt-testing")

	u := &user.User{
		ID:       42,
		Username: "testuser",
		Role:     user.RoleAdmin,
	}

	pair, err := svc.GenerateTokenPair(u)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("access token should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("refresh token should not be empty")
	}
	if pair.AccessToken == pair.RefreshToken {
		t.Error("access and refresh tokens should be different")
	}

	// Validate access token
	claims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Username != "testuser" {
		t.Errorf("Username = %s, want testuser", claims.Username)
	}
	if claims.Role != user.RoleAdmin {
		t.Errorf("Role = %s, want admin", claims.Role)
	}
	if claims.TokenType != tokenTypeAccess {
		t.Errorf("TokenType = %s, want %s", claims.TokenType, tokenTypeAccess)
	}
}

func TestJWTInvalidToken(t *testing.T) {
	svc := NewJWTService("test-secret")

	_, err := svc.ValidateToken("invalid.token.here")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestJWTWrongSecret(t *testing.T) {
	svc1 := NewJWTService("secret-one")
	svc2 := NewJWTService("secret-two")

	u := &user.User{ID: 1, Username: "test", Role: user.RoleEmployee}
	pair, _ := svc1.GenerateTokenPair(u)

	_, err := svc2.ValidateToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error when validating with wrong secret")
	}
}

func TestJWTRejectsWrongTokenType(t *testing.T) {
	svc := NewJWTService("test-secret")
	u := &user.User{ID: 1, Username: "test", Role: user.RoleEmployee}
	pair, _ := svc.GenerateTokenPair(u)

	if _, err := svc.ValidateAccessToken(pair.RefreshToken); err == nil {
		t.Fatal("refresh token should not validate as access token")
	}
	if _, err := svc.ValidateRefreshToken(pair.AccessToken); err == nil {
		t.Fatal("access token should not validate as refresh token")
	}
	if claims, err := svc.ValidateRefreshToken(pair.RefreshToken); err != nil {
		t.Fatalf("refresh token should validate as refresh token: %v", err)
	} else if claims.TokenType != tokenTypeRefresh {
		t.Fatalf("TokenType = %s, want %s", claims.TokenType, tokenTypeRefresh)
	}
}

func TestJWTExpiry(t *testing.T) {
	svc := NewJWTService("test-secret")

	u := &user.User{ID: 1, Username: "test", Role: user.RoleEmployee}
	pair, _ := svc.GenerateTokenPair(u)

	claims, _ := svc.ValidateAccessToken(pair.AccessToken)
	if claims.ExpiresAt == nil {
		t.Fatal("expected expiry to be set")
	}

	expiry := claims.ExpiresAt.Time
	expected := time.Now().Add(15 * time.Minute)

	// Allow 5 second tolerance
	if expiry.Before(expected.Add(-5*time.Second)) || expiry.After(expected.Add(5*time.Second)) {
		t.Errorf("access token expiry %v not within expected range of %v", expiry, expected)
	}
}

func TestJWTDifferentRoles(t *testing.T) {
	svc := NewJWTService("test-secret")

	roles := []user.Role{user.RoleAdmin, user.RoleManager, user.RoleEmployee}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			u := &user.User{ID: 1, Username: "test", Role: role}
			pair, _ := svc.GenerateTokenPair(u)
			claims, err := svc.ValidateAccessToken(pair.AccessToken)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if claims.Role != role {
				t.Errorf("role = %s, want %s", claims.Role, role)
			}
		})
	}
}
