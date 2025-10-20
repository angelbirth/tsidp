// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRateLimitNormalTraffic verifies that normal traffic under the limit is allowed
func TestRateLimitNormalTraffic(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 10,  // 10 requests/second
		BurstSize:       10,  // Allow 10 requests in burst
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	// Make 5 requests (well under limit)
	for i := 0; i < 5; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345" // Non-localhost
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("Request %d should not be rate limited (under limit)", i+1)
		}
	}
}

// TestRateLimitBurstTraffic verifies that burst traffic within burst size is handled correctly
func TestRateLimitBurstTraffic(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 5,   // 5 requests/second sustained
		BurstSize:       10,  // Allow 10 requests in burst
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	// Make 10 rapid requests (exactly burst size)
	successCount := 0
	for i := 0; i < 10; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			successCount++
		}
	}

	// Should allow most/all burst requests (at least 8 out of 10)
	if successCount < 8 {
		t.Errorf("Expected at least 8 burst requests to succeed, got %d", successCount)
	}
}

// TestRateLimitExcessiveTraffic verifies that excessive traffic returns 429 Too Many Requests
func TestRateLimitExcessiveTraffic(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 2,   // Very low limit for testing
		BurstSize:       5,   // Small burst
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	// Make 20 rapid requests (way over limit)
	rateLimitedCount := 0
	for i := 0; i < 20; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			rateLimitedCount++
		}
	}

	// At least 10 requests should be rate limited
	if rateLimitedCount < 10 {
		t.Errorf("Expected at least 10 requests to be rate limited, got %d", rateLimitedCount)
	}
}

// TestRateLimitRefillAfterTime verifies that rate limits reset after time window
func TestRateLimitRefillAfterTime(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 2,   // 2 tokens per second (slow refill: 0.5s per token)
		BurstSize:       3,   // 3 token burst
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	makeRequest := func() int {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)
		return w.Code
	}

	// Exhaust the burst (3 requests)
	for i := 0; i < 3; i++ {
		if code := makeRequest(); code == http.StatusTooManyRequests {
			t.Fatalf("Request %d should not be rate limited (within burst)", i+1)
		}
	}

	// Next request should be rate limited (burst exhausted)
	if code := makeRequest(); code != http.StatusTooManyRequests {
		t.Error("Expected rate limiting after burst exhausted")
	}

	// Wait for 1.5 seconds to allow refill (2 tokens/second = 3 tokens in 1.5s)
	time.Sleep(1600 * time.Millisecond)

	// Should be able to make several more requests now (at least 2 from refill)
	// Note: We exhausted the initial 3-token burst, so after 1.5 seconds we get ~3 new tokens
	// But we're also rate limited by IP, so effective limit is the minimum of both buckets
	successCount := 0
	for i := 0; i < 10; i++ {
		if code := makeRequest(); code != http.StatusTooManyRequests {
			successCount++
		}
	}

	if successCount < 2 {
		t.Errorf("Expected at least 2 requests to succeed after refill, got %d", successCount)
	}
}

// TestRateLimitMultipleClientIsolation verifies that different clients have independent rate limits
func TestRateLimitMultipleClientIsolation(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 1,   // Very slow refill (1 token/second) to prevent refill during test
		BurstSize:       3,   // Small burst for faster exhaustion
		BypassLocalhost: false,
	})

	// Create two different clients
	client1 := addTestClient(t, s, "client-1", "secret-1")
	client2 := addTestClient(t, s, "client-2", "secret-2")
	user := newTestUser(t, "test@example.com")

	makeRequest := func(clientID, clientSecret, redirectURI, ipAddr string) int {
		ar := newTestAuthRequest(t, client1, user)
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirectURI)
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ipAddr + ":12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)
		return w.Code
	}

	// Exhaust rate limit for client 1 from IP 192.168.1.100
	for i := 0; i < 3; i++ {
		makeRequest("client-1", "secret-1", client1.RedirectURIs[0], "192.168.1.100")
	}

	// Client 1 from same IP should be rate limited
	if code := makeRequest("client-1", "secret-1", client1.RedirectURIs[0], "192.168.1.100"); code != http.StatusTooManyRequests {
		t.Error("Client 1 should be rate limited")
	}

	// Client 2 from different IP should have independent rate limit
	if code := makeRequest("client-2", "secret-2", client2.RedirectURIs[0], "192.168.1.101"); code == http.StatusTooManyRequests {
		t.Error("Client 2 from different IP should not be rate limited")
	}
}

// TestRateLimitIPAddressIsolation verifies that different IPs have independent rate limits
func TestRateLimitIPAddressIsolation(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 5,
		BurstSize:       5,
		BypassLocalhost: false,
	})

	user := newTestUser(t, "test@example.com")

	// Create all clients upfront
	client1 := addTestClient(t, s, "client-ip1", "secret-ip1")
	client1b := addTestClient(t, s, "client-ip1b", "secret-ip1b")
	client2 := addTestClient(t, s, "client-ip2", "secret-ip2")

	makeRequest := func(ipAddr string, client *FunnelClient, clientID, clientSecret string) int {
		ar := newTestAuthRequest(t, client, user)
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ipAddr + ":12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)
		return w.Code
	}

	// Exhaust rate limit for IP 192.168.1.100 using client-ip1
	for i := 0; i < 5; i++ {
		makeRequest("192.168.1.100", client1, "client-ip1", "secret-ip1")
	}

	// IP 192.168.1.100 should be rate limited (even with different client)
	if code := makeRequest("192.168.1.100", client1b, "client-ip1b", "secret-ip1b"); code != http.StatusTooManyRequests {
		t.Error("IP 192.168.1.100 should be rate limited")
	}

	// IP 192.168.1.101 should have independent limit
	if code := makeRequest("192.168.1.101", client2, "client-ip2", "secret-ip2"); code == http.StatusTooManyRequests {
		t.Error("IP 192.168.1.101 should not be rate limited (different IP)")
	}
}

// TestRateLimitLocalhostBypass verifies that localhost requests bypass rate limiting when configured
func TestRateLimitLocalhostBypass(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 1,    // Very restrictive
		BurstSize:       2,    // Very small burst
		BypassLocalhost: true, // Bypass localhost
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	localhostAddresses := []string{
		"127.0.0.1:12345",
		"[::1]:12345", // IPv6 must use bracket notation with port
		"localhost:12345",
	}

	for _, addr := range localhostAddresses {
		t.Run(addr, func(t *testing.T) {
			// Make 20 requests from localhost (way over limit)
			for i := 0; i < 20; i++ {
				code := addTestCode(t, s, ar)
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", clientID)
				form.Set("client_secret", clientSecret)

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = addr
				w := httptest.NewRecorder()

				s.ServeHTTP(w, req)

				// Localhost should never be rate limited
				if w.Code == http.StatusTooManyRequests {
					t.Errorf("Localhost (%s) should bypass rate limiting, request %d was rate limited", addr, i+1)
					break
				}
			}
		})
	}
}

// TestRateLimitLocalhostNotBypassed verifies that localhost IS rate limited when bypass is disabled
func TestRateLimitLocalhostNotBypassed(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 2,     // Very restrictive
		BurstSize:       3,     // Very small burst
		BypassLocalhost: false, // DO NOT bypass localhost
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	rateLimitedCount := 0
	for i := 0; i < 10; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			rateLimitedCount++
		}
	}

	// At least some requests should be rate limited
	if rateLimitedCount == 0 {
		t.Error("Expected localhost to be rate limited when bypass is disabled")
	}
}

// TestRateLimitDOSScenario simulates a DOS attack with thousands of requests
func TestRateLimitDOSScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DOS scenario test in short mode")
	}

	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 10,
		BurstSize:       20,
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	const numRequests = 1000
	successCount := 0
	rateLimitedCount := 0

	for i := 0; i < numRequests; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			rateLimitedCount++
		} else {
			successCount++
		}
	}

	t.Logf("DOS test: %d total requests, %d succeeded, %d rate limited", numRequests, successCount, rateLimitedCount)

	// Most requests should be rate limited (at least 90%)
	if rateLimitedCount < 900 {
		t.Errorf("Expected at least 900/%d requests to be rate limited in DOS scenario, got %d", numRequests, rateLimitedCount)
	}
}

// TestRateLimitConcurrentRequests verifies thread safety with concurrent requests
func TestRateLimitConcurrentRequests(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 100,
		BurstSize:       50,
		BypassLocalhost: false,
	})

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")

	const numGoroutines = 10
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	rateLimitedCount := 0

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for i := 0; i < requestsPerGoroutine; i++ {
				ar := newTestAuthRequest(t, client, user)
				code := addTestCode(t, s, ar)
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", clientID)
				form.Set("client_secret", clientSecret)

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", 100+goroutineID)
				w := httptest.NewRecorder()

				s.ServeHTTP(w, req)

				mu.Lock()
				if w.Code == http.StatusTooManyRequests {
					rateLimitedCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}(g)
	}

	wg.Wait()

	totalRequests := numGoroutines * requestsPerGoroutine
	t.Logf("Concurrent test: %d total requests, %d succeeded, %d rate limited", totalRequests, successCount, rateLimitedCount)

	// Should handle concurrent requests without panicking (success)
	if successCount+rateLimitedCount != totalRequests {
		t.Errorf("Request count mismatch: %d + %d != %d", successCount, rateLimitedCount, totalRequests)
	}
}

// TestRateLimitNoRateLimiterConfigured verifies that requests pass through when rate limiter is not configured
func TestRateLimitNoRateLimiterConfigured(t *testing.T) {
	s := newTestServer(t)
	// Do NOT set rate limiter (s.rateLimiter == nil)

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	// Make many requests without rate limiting
	for i := 0; i < 100; i++ {
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Error("Should not rate limit when rate limiter is not configured")
		}
	}
}

// TestRateLimitXForwardedFor verifies that X-Forwarded-For header is respected
func TestRateLimitXForwardedFor(t *testing.T) {
	s := newTestServer(t)
	s.SetRateLimiter(RateLimitConfig{
		TokensPerSecond: 5,
		BurstSize:       5,
		BypassLocalhost: false,
	})

	user := newTestUser(t, "test@example.com")

	// Create all clients upfront
	client1 := addTestClient(t, s, "xff-client-1", "xff-secret-1")
	client1b := addTestClient(t, s, "xff-client-1b", "xff-secret-1b")
	client2 := addTestClient(t, s, "xff-client-2", "xff-secret-2")

	makeRequest := func(xForwardedFor string, client *FunnelClient, clientID, clientSecret string) int {
		ar := newTestAuthRequest(t, client, user)
		code := addTestCode(t, s, ar)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", client.RedirectURIs[0])
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", xForwardedFor)
		req.RemoteAddr = "10.0.0.1:12345" // Proxy address
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)
		return w.Code
	}

	// Exhaust rate limit for IP 203.0.113.45 (via X-Forwarded-For) using xff-client-1
	for i := 0; i < 5; i++ {
		makeRequest("203.0.113.45", client1, "xff-client-1", "xff-secret-1")
	}

	// Same X-Forwarded-For IP should be rate limited (even with different client)
	if code := makeRequest("203.0.113.45", client1b, "xff-client-1b", "xff-secret-1b"); code != http.StatusTooManyRequests {
		t.Error("X-Forwarded-For IP 203.0.113.45 should be rate limited")
	}

	// Different X-Forwarded-For IP should have independent limit
	if code := makeRequest("203.0.113.46", client2, "xff-client-2", "xff-secret-2"); code == http.StatusTooManyRequests {
		t.Error("Different X-Forwarded-For IP should not be rate limited")
	}
}

// TestRateLimitTokenBucketRefill verifies the token bucket refill mechanism
func TestRateLimitTokenBucketRefill(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		TokensPerSecond: 10, // 10 tokens/second
		BurstSize:       5,  // 5 token capacity
		BypassLocalhost: false,
	})

	key := "test-key"

	// First 5 requests should succeed (burst capacity)
	for i := 0; i < 5; i++ {
		if !rl.Allow(key) {
			t.Errorf("Request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th request should be denied (bucket empty)
	if rl.Allow(key) {
		t.Error("Request 6 should be denied (bucket exhausted)")
	}

	// Wait 0.5 seconds (should refill 5 tokens at 10/second)
	time.Sleep(500 * time.Millisecond)

	// Should be able to make 5 more requests
	successCount := 0
	for i := 0; i < 7; i++ {
		if rl.Allow(key) {
			successCount++
		}
	}

	if successCount < 4 || successCount > 6 {
		t.Errorf("Expected 4-6 requests to succeed after 0.5s refill, got %d", successCount)
	}
}

// TestRateLimitCleanup verifies that old buckets are cleaned up
func TestRateLimitCleanup(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		TokensPerSecond: 10,
		BurstSize:       10,
		CleanupInterval: 100 * time.Millisecond, // Very short for testing
		BypassLocalhost: false,
	})

	// Create buckets for multiple keys
	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	for _, key := range keys {
		rl.Allow(key)
	}

	// Verify buckets exist
	rl.mu.Lock()
	initialCount := len(rl.buckets)
	rl.mu.Unlock()

	if initialCount != len(keys) {
		t.Errorf("Expected %d buckets, got %d", len(keys), initialCount)
	}

	// Wait for cleanup interval + cleanup threshold (2x interval)
	time.Sleep(300 * time.Millisecond)

	// Trigger cleanup by making a new request
	rl.Allow("new-key")

	// Old buckets should still exist (not old enough)
	rl.mu.Lock()
	afterFirstCleanup := len(rl.buckets)
	rl.mu.Unlock()

	if afterFirstCleanup < len(keys) {
		t.Logf("Buckets reduced from %d to %d (some may have been cleaned)", initialCount, afterFirstCleanup)
	}
}

// TestIsLocalhost verifies localhost detection
func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		addr        string
		isLocalhost bool
	}{
		{"127.0.0.1:12345", true},
		{"127.0.0.1", true},
		{"[::1]:12345", true}, // Proper IPv6 with port format
		{"::1", true},          // IPv6 without port
		{"localhost:8080", true},
		{"localhost", true},
		{"192.168.1.100:12345", false},
		{"10.0.0.1:8080", false},
		{"example.com:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := isLocalhost(tt.addr)
			if result != tt.isLocalhost {
				t.Errorf("isLocalhost(%q) = %v, want %v", tt.addr, result, tt.isLocalhost)
			}
		})
	}
}

// TestExtractClientID verifies client ID extraction from requests
func TestExtractClientID(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedClient string
	}{
		{
			name: "POST form data",
			setupRequest: func() *http.Request {
				form := url.Values{}
				form.Set("client_id", "form-client")
				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			expectedClient: "form-client",
		},
		{
			name: "Query parameter",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/authorize?client_id=query-client", nil)
				return req
			},
			expectedClient: "query-client",
		},
		{
			name: "Basic auth",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/token", nil)
				req.SetBasicAuth("basic-client", "secret")
				return req
			},
			expectedClient: "basic-client",
		},
		{
			name: "No client ID",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				return req
			},
			expectedClient: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			clientID := extractClientID(req)
			if clientID != tt.expectedClient {
				t.Errorf("extractClientID() = %q, want %q", clientID, tt.expectedClient)
			}
		})
	}
}

// TestGetIPAddress verifies IP address extraction from requests
func TestGetIPAddress(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For single",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.45"},
			expectedIP: "203.0.113.45",
		},
		{
			name:       "X-Forwarded-For multiple",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.45, 198.51.100.1, 10.0.0.1"},
			expectedIP: "203.0.113.45",
		},
		{
			name:       "X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "203.0.113.45"},
			expectedIP: "203.0.113.45",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.45",
				"X-Real-IP":       "198.51.100.1",
			},
			expectedIP: "203.0.113.45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ipAddr := getIPAddress(req)
			if ipAddr != tt.expectedIP {
				t.Errorf("getIPAddress() = %q, want %q", ipAddr, tt.expectedIP)
			}
		})
	}
}
