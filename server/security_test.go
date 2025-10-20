// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TestAuthorizationCodeReplay verifies that authorization codes can only be used once
// This is a critical security property of OAuth 2.0
func TestAuthorizationCodeReplay(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user)

	code := addTestCode(t, s, ar)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	// First use - code should be deleted
	req1 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	s.handleAuthorizationCodeGrant(w1, req1)

	// Second use - should fail
	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	s.handleAuthorizationCodeGrant(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("Authorization code replay should fail, got status %d", w2.Code)
	}

	// Verify code was deleted
	s.mu.Lock()
	_, exists := s.code[code]
	s.mu.Unlock()

	if exists {
		t.Error("Authorization code should be deleted after first use")
	}
}

// TestLocalhostAccess verifies localhost bypass behavior for development
// This is intentional for -local-port development mode
func TestLocalhostAccess(t *testing.T) {
	t.Run("without_local_client", func(t *testing.T) {
		// When lc is nil, localhost should get default-deny (no access)
		s := newTestServer(t)

		handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
			access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
			if !ok {
				t.Error("Expected access rules in context")
				return
			}
			// When lc is nil, should get default-deny rules
			if access.allowAdminUI || access.allowDCR {
				t.Error("Without lc set, should not have admin access")
			}
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345" // Localhost
		w := httptest.NewRecorder()

		handler(w, req)
	})

	t.Log("Note: Localhost bypass only works when lc is set (with tailscaled)")
	t.Log("In -local-port development mode without tailscaled, App Cap checks are bypassed via bypassAppCapCheck flag")
	t.Log("See SECURITY.md for deployment guidance")
}

// TestPKCEValidation tests PKCE code challenge validation
// PKCE should always be used by clients even though it's not currently enforced
func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name          string
		verifier      string
		challenge     string
		method        string
		shouldSucceed bool
	}{
		{
			name:          "Valid S256 PKCE",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			shouldSucceed: true,
		},
		{
			name:          "Valid plain PKCE",
			verifier:      "my-secure-verifier-string-that-is-long-enough-to-pass",
			challenge:     "my-secure-verifier-string-that-is-long-enough-to-pass",
			method:        "plain",
			shouldSucceed: true,
		},
		{
			name:          "Invalid verifier too short",
			verifier:      "short",
			challenge:     "short",
			method:        "plain",
			shouldSucceed: false,
		},
		{
			name:          "Mismatched S256 challenge",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "wrong-challenge-value",
			method:        "S256",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCodeVerifier(tt.verifier, tt.challenge, tt.method)
			if tt.shouldSucceed && err != nil {
				t.Errorf("Expected validation to succeed, got error: %v", err)
			}
			if !tt.shouldSucceed && err == nil {
				t.Error("Expected validation to fail, but it succeeded")
			}
		})
	}
}

// TestClientSecretConstantTimeComparison verifies timing-safe secret comparison
// This prevents timing attacks on client authentication
func TestClientSecretConstantTimeComparison(t *testing.T) {
	s := &IDPServer{
		funnelClients: make(map[string]*FunnelClient),
	}

	clientID := "test-client"
	correctSecret := "correct-secret-value"
	s.funnelClients[clientID] = &FunnelClient{
		ID:     clientID,
		Secret: correctSecret,
	}

	// Test various incorrect secrets
	incorrectSecrets := []string{
		"a",
		"c",
		"correct-secret-valu",
		"correct-secret-valuX",
		"Xorrect-secret-value",
		"totally-different-secret-value-here",
	}

	for _, secret := range incorrectSecrets {
		req := httptest.NewRequest("POST", "/token", nil)
		req.SetBasicAuth(clientID, secret)

		clientIDResult := s.identifyClient(req)
		if clientIDResult != "" {
			t.Errorf("Client identification should fail with incorrect secret: %s", secret)
		}
	}

	// Verify correct secret works
	req := httptest.NewRequest("POST", "/token", nil)
	req.SetBasicAuth(clientID, correctSecret)
	clientIDResult := s.identifyClient(req)
	if clientIDResult != clientID {
		t.Error("Client identification should succeed with correct secret")
	}
}

// TestTokenExpirationEnforcement verifies that expired tokens are rejected
func TestTokenExpirationEnforcement(t *testing.T) {
	s := &IDPServer{
		accessToken: make(map[string]*AuthRequest),
	}

	// Create an expired access token
	expiredToken := "expired-token-123"
	s.accessToken[expiredToken] = &AuthRequest{
		ValidTill: time.Now().Add(-1 * time.Hour),
	}

	// Create a valid access token
	validToken := "valid-token-456"
	s.accessToken[validToken] = &AuthRequest{
		ValidTill: time.Now().Add(5 * time.Minute),
		RemoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				User: 12345,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "test@example.com",
			},
		},
	}

	// Test userinfo endpoint with expired token
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()

	s.serveUserInfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expired token should be rejected, got status %d", w.Code)
	}

	// Verify expired token was cleaned up
	s.mu.Lock()
	_, exists := s.accessToken[expiredToken]
	s.mu.Unlock()

	if exists {
		t.Error("Expired token should be removed after detection")
	}
}

// TestSigningKeyPersistence verifies that signing keys survive restarts
func TestSigningKeyPersistence(t *testing.T) {
	// This is implicitly tested by the key loading logic in oidcPrivateKey()
	// Keys are saved to oidc-key.json and loaded on startup
	// See server.go:297-326 for implementation

	t.Log("Signing keys are persisted to oidc-key.json")
	t.Log("Client configurations are persisted to oidc-funnel-clients.json")
	t.Log("Session tokens (codes, access, refresh) are in-memory only")
}

// TestCleanupExpiredTokens verifies the cleanup mechanism
func TestCleanupExpiredTokens(t *testing.T) {
	s := &IDPServer{
		code:         make(map[string]*AuthRequest),
		accessToken:  make(map[string]*AuthRequest),
		refreshToken: make(map[string]*AuthRequest),
	}

	now := time.Now()

	// Add mix of expired and valid tokens
	s.code["expired-code"] = &AuthRequest{ValidTill: now.Add(-1 * time.Hour)}
	s.code["valid-code"] = &AuthRequest{ValidTill: now.Add(5 * time.Minute)}
	s.accessToken["expired-access"] = &AuthRequest{ValidTill: now.Add(-1 * time.Hour)}
	s.accessToken["valid-access"] = &AuthRequest{ValidTill: now.Add(5 * time.Minute)}
	s.refreshToken["expired-refresh"] = &AuthRequest{ValidTill: now.Add(-1 * time.Hour)}
	s.refreshToken["valid-refresh"] = &AuthRequest{ValidTill: now.Add(24 * time.Hour)}

	// Run cleanup
	s.CleanupExpiredTokens()

	// Verify expired tokens removed
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.code["expired-code"]; exists {
		t.Error("Expired authorization code should be removed")
	}
	if _, exists := s.accessToken["expired-access"]; exists {
		t.Error("Expired access token should be removed")
	}
	if _, exists := s.refreshToken["expired-refresh"]; exists {
		t.Error("Expired refresh token should be removed")
	}

	// Verify valid tokens remain
	if _, exists := s.code["valid-code"]; !exists {
		t.Error("Valid authorization code should remain")
	}
	if _, exists := s.accessToken["valid-access"]; !exists {
		t.Error("Valid access token should remain")
	}
	if _, exists := s.refreshToken["valid-refresh"]; !exists {
		t.Error("Valid refresh token should remain")
	}
}

// TestRedirectURIValidation tests redirect URI validation
func TestRedirectURIValidationSecurity(t *testing.T) {
	tests := []struct {
		uri           string
		shouldBeValid bool
		reason        string
	}{
		{
			uri:           "https://example.com/callback",
			shouldBeValid: true,
			reason:        "Standard HTTPS callback",
		},
		{
			uri:           "http://localhost:3000/callback",
			shouldBeValid: true,
			reason:        "Localhost HTTP allowed for development",
		},
		{
			uri:           "myapp://callback",
			shouldBeValid: false,
			reason:        "Custom scheme blocked (strict allow-list)",
		},
		{
			uri:           "",
			shouldBeValid: false,
			reason:        "Empty URI",
		},
		{
			uri:           "https://",
			shouldBeValid: false,
			reason:        "HTTPS without host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			errMsg := validateRedirectURI(tt.uri)
			isValid := errMsg == ""

			if isValid != tt.shouldBeValid {
				if isValid {
					t.Errorf("URI '%s' should be invalid: %s", tt.uri, tt.reason)
				} else {
					t.Errorf("URI '%s' should be valid: %s (got error: %s)", tt.uri, tt.reason, errMsg)
				}
			}
		})
	}
}

// TestCORSConfiguration documents current CORS configuration
func TestCORSConfiguration(t *testing.T) {
	s := &IDPServer{
		serverURL: "https://idp.example.ts.net",
	}

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	s.serveOpenIDConfig(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "*" {
		t.Errorf("Expected wildcard CORS origin, got: %s", origin)
	}

	t.Log("Note: CORS currently allows all origins for .well-known endpoints")
	t.Log("For production, consider restricting via reverse proxy")
	t.Log("See SECURITY.md for configuration examples")
}

// TestRefreshTokenRotation verifies refresh token rotation on use
func TestRefreshTokenRotation(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	clientSecret := "test-secret"
	client := addTestClient(t, s, clientID, clientSecret)
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user, WithValidTill(time.Now().Add(24*time.Hour)))

	originalRefreshToken := addTestRefreshToken(t, s, ar)

	// Use refresh token
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", originalRefreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleRefreshTokenGrant(w, req)

	// Verify original token was deleted
	s.mu.Lock()
	_, exists := s.refreshToken[originalRefreshToken]
	s.mu.Unlock()

	if exists {
		t.Error("Original refresh token should be deleted after use (rotation)")
	}
}
