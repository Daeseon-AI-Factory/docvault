package web

import (
	"testing"
	"time"
)

func TestRateLimiterLocksAfterMaxAttempts(t *testing.T) {
	rl := NewLoginRateLimiter(3, 10*time.Minute, 15*time.Minute)

	ip := "192.168.1.100"

	// First 2 failures: not locked
	for i := 0; i < 2; i++ {
		locked := rl.RecordFailure(ip)
		if locked {
			t.Fatalf("should not be locked after %d failures", i+1)
		}
	}

	// 3rd failure: locked
	locked := rl.RecordFailure(ip)
	if !locked {
		t.Error("should be locked after 3 failures")
	}

	if !rl.IsLocked(ip) {
		t.Error("IsLocked should return true")
	}
}

func TestRateLimiterClearsOnSuccess(t *testing.T) {
	rl := NewLoginRateLimiter(3, 10*time.Minute, 15*time.Minute)
	ip := "10.0.0.1"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	rl.RecordSuccess(ip)

	if rl.IsLocked(ip) {
		t.Error("should not be locked after success")
	}
	if rl.RemainingAttempts(ip) != 3 {
		t.Errorf("expected 3 remaining, got %d", rl.RemainingAttempts(ip))
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewLoginRateLimiter(2, 10*time.Minute, 15*time.Minute)

	rl.RecordFailure("10.0.0.1")
	rl.RecordFailure("10.0.0.1")

	if !rl.IsLocked("10.0.0.1") {
		t.Error("10.0.0.1 should be locked")
	}
	if rl.IsLocked("10.0.0.2") {
		t.Error("10.0.0.2 should not be locked")
	}
}

func TestRateLimiterRemainingAttempts(t *testing.T) {
	rl := NewLoginRateLimiter(5, 10*time.Minute, 15*time.Minute)
	ip := "172.16.0.1"

	if rl.RemainingAttempts(ip) != 5 {
		t.Errorf("expected 5, got %d", rl.RemainingAttempts(ip))
	}

	rl.RecordFailure(ip)
	if rl.RemainingAttempts(ip) != 4 {
		t.Errorf("expected 4, got %d", rl.RemainingAttempts(ip))
	}

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	if rl.RemainingAttempts(ip) != 2 {
		t.Errorf("expected 2, got %d", rl.RemainingAttempts(ip))
	}
}

func TestRateLimiterUnlockedIP(t *testing.T) {
	rl := NewLoginRateLimiter(3, 10*time.Minute, 15*time.Minute)
	if rl.IsLocked("1.2.3.4") {
		t.Error("unknown IP should not be locked")
	}
}
