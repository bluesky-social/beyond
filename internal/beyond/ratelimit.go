package beyond

import (
	"sync"
	"time"
)

// ipRateLimiter provides simple per-IP rate limiting using a fixed time window.
// It is designed for lightweight abuse prevention (e.g. OIDC login floods), not
// precise rate control. At window boundaries a client may briefly get up to 2x
// the configured limit — acceptable for this use case.
type ipRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	resetAt time.Time
	window  time.Duration
	limit   int
}

// newIPRateLimiter creates a rate limiter that allows limit requests per IP
// within each window duration.
func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(window),
		window:  window,
		limit:   limit,
	}
}

// Allow returns true if the given IP has not exceeded the rate limit.
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.maybeReset()
	rl.counts[ip]++
	return rl.counts[ip] <= rl.limit
}

// Refund returns one previously-consumed slot for ip. Pair with Allow for
// flows that only want selected outcomes to count (e.g. only failed auth
// attempts): consume atomically upfront via Allow — a check-then-record
// split would leave a TOCTOU window where a concurrent burst all passes the
// check before any failure is recorded — then Refund on success. A refund
// after the window rolled over is harmlessly absorbed by the zero floor.
func (rl *ipRateLimiter) Refund(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.maybeReset()
	if rl.counts[ip] > 0 {
		rl.counts[ip]--
	}
}

// maybeReset clears the window if it has elapsed. Callers must hold rl.mu.
func (rl *ipRateLimiter) maybeReset() {
	now := time.Now()
	if now.After(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = now.Add(rl.window)
	}
}
