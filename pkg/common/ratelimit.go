package common

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter provides thread-safe rate limiting with dynamically adjustable limits.
// It helps prevent overwhelming downstream services by controlling request rates
// while allowing runtime adjustments based on service conditions.
type RateLimiter struct {
	limiter *rate.Limiter
	mu      sync.RWMutex // Protects concurrent access to the limiter
}

// NewRateLimiter creates a RateLimiter with the specified requests per second (rps)
// and burst size. The burst parameter controls how many requests can be made at once
// to accommodate temporary spikes in traffic.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

// Wait blocks until the rate limiter allows an event or the context is canceled.
// It returns an error if the context is canceled while waiting.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.limiter.Wait(ctx)
}

// UpdateLimits dynamically adjusts the rate limiter's requests per second and burst size.
// This allows adapting to changing conditions like server load or API quotas at runtime.
func (rl *RateLimiter) UpdateLimits(rps float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiter.SetLimit(rate.Limit(rps))
	rl.limiter.SetBurst(burst)
}
