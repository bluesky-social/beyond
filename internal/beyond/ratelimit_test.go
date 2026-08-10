package beyond

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIPRateLimiter_AllowsUnderLimit(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(3, time.Minute)
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.1"))
}

func TestIPRateLimiter_DeniesOverLimit(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(2, time.Minute)
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.False(t, rl.Allow("10.0.0.1"), "should deny after exceeding limit")
}

func TestIPRateLimiter_SeparateIPs(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(1, time.Minute)
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.2"), "different IPs should have independent limits")
	assert.False(t, rl.Allow("10.0.0.1"), "original IP should still be limited")
}

func TestIPRateLimiter_ResetsAfterWindow(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(1, 10*time.Millisecond)
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.False(t, rl.Allow("10.0.0.1"))

	time.Sleep(20 * time.Millisecond)
	assert.True(t, rl.Allow("10.0.0.1"), "should allow again after window reset")
}

// TestIPRateLimiter_RefundRestoresSlot covers the consume-then-refund pattern
// the bearer failure limiter relies on: each successful verification refunds
// the slot it consumed, so a healthy client never exhausts the budget.
func TestIPRateLimiter_RefundRestoresSlot(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(2, time.Minute)
	// Simulate many successful requests: each consumes a slot via Allow and
	// refunds it on success. The budget must never be exhausted.
	for range 10 {
		assert.True(t, rl.Allow("10.0.0.1"), "consume-then-refund must keep slots available")
		rl.Refund("10.0.0.1")
	}
	// Two genuine failures (no refund) then a third must be denied.
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.False(t, rl.Allow("10.0.0.1"), "unrefunded consumption still hits the limit")
}

// TestIPRateLimiter_RefundZeroFloorAcrossRollover covers the documented branch
// in Refund: a refund after the window rolled over (counter reset to 0) must
// be harmlessly absorbed by the zero floor, never producing a negative count
// that would grant extra budget.
func TestIPRateLimiter_RefundZeroFloorAcrossRollover(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(2, 10*time.Millisecond)
	assert.True(t, rl.Allow("10.0.0.1")) // count = 1

	// Let the window roll over so the next op resets the counter to 0.
	time.Sleep(20 * time.Millisecond)
	rl.Refund("10.0.0.1") // refund on a fresh (count==0) window must floor at 0

	// The full budget must be available — the refund must not have driven the
	// count negative and granted a 3rd allow.
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.True(t, rl.Allow("10.0.0.1"))
	assert.False(t, rl.Allow("10.0.0.1"), "zero-floored refund must not grant extra budget")
}
