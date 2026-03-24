package user

import "testing"

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("mypassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}
	if hash == "mypassword123" {
		t.Error("hash should not equal plaintext")
	}

	// Different calls should produce different hashes (bcrypt salt)
	hash2, _ := HashPassword("mypassword123")
	if hash == hash2 {
		t.Error("two hashes of same password should differ (random salt)")
	}
}

func TestCheckPassword(t *testing.T) {
	hash, _ := HashPassword("correctpassword")

	if err := CheckPassword(hash, "correctpassword"); err != nil {
		t.Error("CheckPassword should succeed with correct password")
	}

	if err := CheckPassword(hash, "wrongpassword"); err == nil {
		t.Error("CheckPassword should fail with wrong password")
	}
}

func TestRoleConstants(t *testing.T) {
	if RoleAdmin != "admin" {
		t.Errorf("RoleAdmin = %s, want admin", RoleAdmin)
	}
	if RoleManager != "manager" {
		t.Errorf("RoleManager = %s, want manager", RoleManager)
	}
	if RoleEmployee != "employee" {
		t.Errorf("RoleEmployee = %s, want employee", RoleEmployee)
	}
}
