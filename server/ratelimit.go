// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting
// Supports both per-client ID and per-IP address limiting
type RateLimiter struct {
	mu               sync.Mutex
	buckets          map[string]*tokenBucket
	tokensPerSecond  float64
	burstSize        int
	cleanupInterval  time.Duration
	lastCleanup      time.Time
	bypassLocalhost  bool
}

// tokenBucket implements the token bucket algorithm
type tokenBucket struct {
	tokens         float64
	lastRefillTime time.Time
}

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	// TokensPerSecond is the sustained rate limit (requests/second)
	TokensPerSecond float64

	// BurstSize is the maximum number of requests that can be made in a burst
	BurstSize int

	// CleanupInterval is how often to clean up old buckets (default: 10 minutes)
	CleanupInterval time.Duration

	// BypassLocalhost allows localhost requests to bypass rate limiting (for testing)
	BypassLocalhost bool
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 10 * time.Minute
	}

	return &RateLimiter{
		buckets:          make(map[string]*tokenBucket),
		tokensPerSecond:  config.TokensPerSecond,
		burstSize:        config.BurstSize,
		cleanupInterval:  config.CleanupInterval,
		lastCleanup:      time.Now(),
		bypassLocalhost:  config.BypassLocalhost,
	}
}

// Allow checks if a request should be allowed based on rate limiting
// key is typically either a client ID or IP address
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Cleanup old buckets periodically
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		rl.cleanup(now)
		rl.lastCleanup = now
	}

	// Get or create bucket for this key
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &tokenBucket{
			tokens:         float64(rl.burstSize),
			lastRefillTime: now,
		}
		rl.buckets[key] = bucket
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(bucket.lastRefillTime).Seconds()
	bucket.tokens += elapsed * rl.tokensPerSecond

	// Cap at burst size
	if bucket.tokens > float64(rl.burstSize) {
		bucket.tokens = float64(rl.burstSize)
	}

	bucket.lastRefillTime = now

	// Check if we have at least 1 token
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

// cleanup removes buckets that haven't been used recently
func (rl *RateLimiter) cleanup(now time.Time) {
	threshold := now.Add(-rl.cleanupInterval * 2)
	for key, bucket := range rl.buckets {
		if bucket.lastRefillTime.Before(threshold) {
			delete(rl.buckets, key)
		}
	}
}

// isLocalhost checks if the given address is localhost
func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port or parsing failed, treat the whole string as host
		// This handles cases like "localhost", "127.0.0.1", "::1"
		host = addr

		// Also try stripping brackets for IPv6 addresses like "[::1]"
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
	}

	// Check for localhost names
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	// Check if it's a loopback IP
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}

	return false
}

// extractClientID tries to extract client_id from the request
// Returns empty string if not found
func extractClientID(r *http.Request) string {
	// Try POST form data first (for /token endpoint)
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			if clientID := r.PostForm.Get("client_id"); clientID != "" {
				return clientID
			}
		}
	}

	// Try query parameters (for /authorize endpoint)
	if clientID := r.URL.Query().Get("client_id"); clientID != "" {
		return clientID
	}

	// Try Basic Auth
	username, _, ok := r.BasicAuth()
	if ok && username != "" {
		return username
	}

	return ""
}

// getIPAddress extracts the IP address from the request
// Handles X-Forwarded-For and X-Real-IP headers for proxied requests
func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header (proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (proxy)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimitMiddleware returns an HTTP middleware that enforces rate limiting
func (s *IDPServer) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If rate limiting is not configured, pass through
		if s.rateLimiter == nil {
			next(w, r)
			return
		}

		// Bypass rate limiting for localhost if configured
		if s.rateLimiter.bypassLocalhost && isLocalhost(r.RemoteAddr) {
			next(w, r)
			return
		}

		// Try to rate limit by client ID first (more specific)
		clientID := extractClientID(r)
		if clientID != "" {
			if !s.rateLimiter.Allow("client:" + clientID) {
				writeHTTPError(w, r, http.StatusTooManyRequests, ecServerError,
					"Rate limit exceeded for client. Please try again later.", nil)
				return
			}
		}

		// Also rate limit by IP address (defense against abuse)
		ipAddr := getIPAddress(r)
		if ipAddr != "" {
			if !s.rateLimiter.Allow("ip:" + ipAddr) {
				writeHTTPError(w, r, http.StatusTooManyRequests, ecServerError,
					"Rate limit exceeded for IP address. Please try again later.", nil)
				return
			}
		}

		// Request is allowed, proceed to next handler
		next(w, r)
	}
}
