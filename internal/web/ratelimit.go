package web

import (
	"net/http"
	"sync"
	"time"
)

// LoginRateLimiter tracks failed login attempts per IP.
// After maxAttempts failures within the window, the IP is locked for lockDuration.
type LoginRateLimiter struct {
	mu          sync.Mutex
	attempts    map[string]*attemptRecord
	maxAttempts int
	window      time.Duration
	lockDuration time.Duration
}

type attemptRecord struct {
	failures  int
	firstFail time.Time
	lockedAt  time.Time
}

func NewLoginRateLimiter(maxAttempts int, window, lockDuration time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		attempts:    make(map[string]*attemptRecord),
		maxAttempts: maxAttempts,
		window:      window,
		lockDuration: lockDuration,
	}
	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

// IsLocked returns true if the IP is currently locked out.
func (rl *LoginRateLimiter) IsLocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		return false
	}

	// Lock expired?
	if !rec.lockedAt.IsZero() && time.Since(rec.lockedAt) > rl.lockDuration {
		delete(rl.attempts, ip)
		return false
	}

	return !rec.lockedAt.IsZero()
}

// RecordFailure records a failed login attempt. Returns true if the IP is now locked.
func (rl *LoginRateLimiter) RecordFailure(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		rec = &attemptRecord{firstFail: time.Now()}
		rl.attempts[ip] = rec
	}

	// Reset if outside window
	if time.Since(rec.firstFail) > rl.window {
		rec.failures = 0
		rec.firstFail = time.Now()
		rec.lockedAt = time.Time{}
	}

	rec.failures++

	if rec.failures >= rl.maxAttempts {
		rec.lockedAt = time.Now()
		return true
	}

	return false
}

// RecordSuccess clears the record for a successful login.
func (rl *LoginRateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

// RemainingAttempts returns how many attempts remain before lockout.
func (rl *LoginRateLimiter) RemainingAttempts(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		return rl.maxAttempts
	}

	if time.Since(rec.firstFail) > rl.window {
		return rl.maxAttempts
	}

	remaining := rl.maxAttempts - rec.failures
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (rl *LoginRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.lockDuration - rl.window)
	for ip, rec := range rl.attempts {
		if rec.firstFail.Before(cutoff) {
			delete(rl.attempts, ip)
		}
	}
}

// ExtractIP gets the client IP from a request (handles X-Forwarded-For).
func ExtractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
