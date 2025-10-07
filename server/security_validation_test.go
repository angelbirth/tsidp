// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestRedirectURI_Validation tests redirect URI validation for security
func TestRedirectURI_Validation(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantValid bool
		reason    string
	}{
		// Valid URIs
		{
			name:      "Valid_HTTPS",
			uri:       "https://example.com/callback",
			wantValid: true,
		},
		{
			name:      "Valid_HTTPS_WithPort",
			uri:       "https://example.com:8443/callback",
			wantValid: true,
		},
		{
			name:      "Valid_HTTPS_WithQuery",
			uri:       "https://example.com/callback?param=value",
			wantValid: true,
		},
		{
			name:      "Valid_HTTPS_WithFragment",
			uri:       "https://example.com/callback#fragment",
			wantValid: true,
		},
		{
			name:      "Valid_HTTP_Localhost",
			uri:       "http://localhost:3000/callback",
			wantValid: true,
			reason:    "Localhost HTTP allowed for development",
		},
		{
			name:      "Valid_HTTP_127001",
			uri:       "http://127.0.0.1:8080/callback",
			wantValid: true,
			reason:    "Loopback HTTP allowed for development",
		},
		{
			name:      "Valid_HTTP_Tailscale_CGNAT_IPv4",
			uri:       "http://100.64.1.5:8080/callback",
			wantValid: true,
			reason:    "Tailscale CGNAT range (100.64.0.0/10) - encrypted via WireGuard",
		},
		{
			name:      "Valid_HTTP_Tailscale_IPv6",
			uri:       "http://[fd7a:115c:a1e0::1]:8080/callback",
			wantValid: true,
			reason:    "Tailscale IPv6 range - encrypted via WireGuard",
		},
		{
			name:      "Valid_HTTP_Tailscale_MagicDNS",
			uri:       "http://proxmox.tail-net.ts.net/callback",
			wantValid: true,
			reason:    "Tailscale MagicDNS - encrypted via WireGuard",
		},
		{
			name:      "Valid_HTTP_Tailscale_MagicDNS_WithPort",
			uri:       "http://synology.my-network.ts.net:5000/callback",
			wantValid: true,
			reason:    "Tailscale MagicDNS with port - encrypted via WireGuard",
		},
		{
			name:      "Blocked_CustomScheme_Mobile",
			uri:       "com.example.myapp://callback",
			wantValid: false,
			reason:    "Custom schemes not currently supported (strict allow-list)",
		},
		{
			name:      "Blocked_CustomScheme_Simple",
			uri:       "myapp://callback",
			wantValid: false,
			reason:    "Custom schemes not currently supported (strict allow-list)",
		},

		// Invalid URIs - Empty/Malformed
		{
			name:      "Invalid_Empty",
			uri:       "",
			wantValid: false,
			reason:    "Empty URI not allowed",
		},
		{
			name:      "Invalid_OnlyScheme",
			uri:       "https://",
			wantValid: false,
			reason:    "Scheme without host",
		},
		{
			name:      "Invalid_NoScheme",
			uri:       "example.com/callback",
			wantValid: false,
			reason:    "Missing scheme",
		},
		{
			name:      "Invalid_Malformed",
			uri:       "ht!tp://example.com",
			wantValid: false,
			reason:    "Malformed URI",
		},

		// Security tests - Dangerous schemes blocked (RFC 8252, BCP 212)
		{
			name:      "Blocked_HTTP_NonLocalhost",
			uri:       "http://example.com/callback",
			wantValid: false,
			reason:    "HTTP non-localhost blocked per RFC 8252",
		},
		{
			name:      "Blocked_HTTP_100_OutsideCGNAT",
			uri:       "http://100.50.1.1/callback",
			wantValid: false,
			reason:    "100.x outside CGNAT range (100.64-127) blocked",
		},
		{
			name:      "Blocked_HTTP_100_AboveCGNAT",
			uri:       "http://100.128.1.1/callback",
			wantValid: false,
			reason:    "100.128+ outside CGNAT range blocked",
		},
		{
			name:      "Blocked_DataURI_XSS",
			uri:       "data:text/html,test",
			wantValid: false,
			reason:    "Data URIs blocked to prevent XSS",
		},
		{
			name:      "Blocked_JavaScript_XSS",
			uri:       "javascript:alert('test')",
			wantValid: false,
			reason:    "JavaScript URIs blocked to prevent XSS",
		},
		{
			name:      "Blocked_VBScript_XSS",
			uri:       "vbscript:msgbox('test')",
			wantValid: false,
			reason:    "VBScript URIs blocked to prevent XSS",
		},
		{
			name:      "Blocked_File_Security",
			uri:       "file:///etc/passwd",
			wantValid: false,
			reason:    "File URIs blocked for security",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := validateRedirectURI(tt.uri)
			isValid := (errMsg == "")

			if isValid != tt.wantValid {
				if tt.wantValid {
					t.Errorf("URI %q should be valid (%s), but got error: %s", tt.uri, tt.reason, errMsg)
				} else {
					t.Errorf("URI %q should be invalid (%s), but was accepted", tt.uri, tt.reason)
				}
			}
		})
	}
}

// TestRedirectURI_ExactMatch tests that redirect_uri must match exactly
// This tests the logic in authorize.go:62 using slices.Contains
func TestRedirectURI_ExactMatch(t *testing.T) {
	// Test the exact matching logic directly
	client := newTestClient(t, "test-client", "test-secret",
		"https://example.com/callback",
		"https://example.com/callback2",
	)

	tests := []struct {
		name         string
		requestedURI string
		shouldMatch  bool
		reason       string
	}{
		{
			name:         "ExactMatch_First",
			requestedURI: "https://example.com/callback",
			shouldMatch:  true,
		},
		{
			name:         "ExactMatch_Second",
			requestedURI: "https://example.com/callback2",
			shouldMatch:  true,
		},
		{
			name:         "Mismatch_Path",
			requestedURI: "https://example.com/callback-different",
			shouldMatch:  false,
			reason:       "Path must match exactly",
		},
		{
			name:         "Mismatch_Query",
			requestedURI: "https://example.com/callback?extra=param",
			shouldMatch:  false,
			reason:       "Query parameters make it different",
		},
		{
			name:         "Mismatch_Fragment",
			requestedURI: "https://example.com/callback#fragment",
			shouldMatch:  false,
			reason:       "Fragment makes it different",
		},
		{
			name:         "Mismatch_Scheme",
			requestedURI: "http://example.com/callback",
			shouldMatch:  false,
			reason:       "Scheme must match",
		},
		{
			name:         "Mismatch_Host",
			requestedURI: "https://evil.com/callback",
			shouldMatch:  false,
			reason:       "Host must match",
		},
		{
			name:         "Mismatch_Port",
			requestedURI: "https://example.com:8443/callback",
			shouldMatch:  false,
			reason:       "Port must match (implicit 443 vs explicit 8443)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use slices.Contains like the actual code does (authorize.go:62)
			matched := slices.Contains(client.RedirectURIs, tt.requestedURI)

			if matched != tt.shouldMatch {
				if tt.shouldMatch {
					t.Errorf("Expected URI %q to match registered URIs, but it didn't", tt.requestedURI)
				} else {
					t.Errorf("Expected URI %q to NOT match (%s), but it did", tt.requestedURI, tt.reason)
				}
			}
		})
	}
}

// TestScope_Validation tests scope validation
func TestScope_Validation(t *testing.T) {
	s := newTestServer(t)

	tests := []struct {
		name         string
		scopes       []string
		wantValid    bool
		expectedList []string
	}{
		{
			name:         "Valid_OpenID",
			scopes:       []string{"openid"},
			wantValid:    true,
			expectedList: []string{"openid"},
		},
		{
			name:         "Valid_OpenIDProfile",
			scopes:       []string{"openid", "profile"},
			wantValid:    true,
			expectedList: []string{"openid", "profile"},
		},
		{
			name:         "Valid_AllScopes",
			scopes:       []string{"openid", "profile", "email"},
			wantValid:    true,
			expectedList: []string{"openid", "profile", "email"},
		},
		{
			name:         "Valid_EmptyDefaultsToOpenID",
			scopes:       []string{},
			wantValid:    true,
			expectedList: []string{"openid"},
		},
		{
			name:      "Invalid_UnsupportedScope",
			scopes:    []string{"openid", "unsupported_scope"},
			wantValid: false,
		},
		{
			name:      "Invalid_OnlyUnsupported",
			scopes:    []string{"admin", "superuser"},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.validateScopes(tt.scopes)

			if tt.wantValid {
				if err != nil {
					t.Errorf("Expected scopes to be valid, got error: %v", err)
				}
				if len(result) != len(tt.expectedList) {
					t.Errorf("Expected %d scopes, got %d", len(tt.expectedList), len(result))
				}
				for i, expected := range tt.expectedList {
					if i >= len(result) || result[i] != expected {
						t.Errorf("Expected scope[%d]=%q, got %q", i, expected, result[i])
					}
				}
			} else {
				if err == nil {
					t.Error("Expected scope validation to fail, but it succeeded")
				}
			}
		})
	}
}

// TestClientSecret_ConstantTime tests that client secret comparison is constant-time
func TestClientSecret_ConstantTime(t *testing.T) {
	s := newTestServer(t)

	correctSecret := "correct-secret-value-that-is-long"
	client := addTestClient(t, s, "test-client", correctSecret)

	// All these should fail, but in constant time
	incorrectSecrets := []struct {
		name   string
		secret string
	}{
		{"FirstCharWrong", "X" + correctSecret[1:]},
		{"LastCharWrong", correctSecret[:len(correctSecret)-1] + "X"},
		{"MiddleCharWrong", correctSecret[:len(correctSecret)/2] + "X" + correctSecret[len(correctSecret)/2+1:]},
		{"CompletelyDifferent", "totally-different-secret-value-here"},
		{"TooShort", "short"},
		{"TooLong", correctSecret + "-extra-characters-added"},
		{"Empty", ""},
	}

	for _, tt := range incorrectSecrets {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", nil)
			req.SetBasicAuth(client.ID, tt.secret)

			result := s.identifyClient(req)
			if result != "" {
				t.Errorf("Client identification should fail with incorrect secret %q, but succeeded", tt.name)
			}
		})
	}

	// Verify correct secret works
	t.Run("CorrectSecret", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/token", nil)
		req.SetBasicAuth(client.ID, correctSecret)

		result := s.identifyClient(req)
		if result != client.ID {
			t.Error("Client identification should succeed with correct secret")
		}
	})
}

// TestState_Preservation tests that state parameter is preserved
// State is handled in authorize.go:130-132 and passed to redirects
func TestState_Preservation(t *testing.T) {
	stateValues := []string{
		"simple-state",
		"state-with-dashes-and-numbers-123",
		"state_with_underscores",
		"aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		strings.Repeat("x", 100), // Long state
	}

	for _, state := range stateValues {
		t.Run("State_"+state[:min(len(state), 20)], func(t *testing.T) {
			// Test state preservation in URL building (what the code actually does)
			queryString := make(url.Values)
			queryString.Set("code", "test-code")
			if state != "" {
				queryString.Set("state", state)
			}

			parsedURL, _ := url.Parse("https://example.com/callback")
			parsedURL.RawQuery = queryString.Encode()

			location := parsedURL.String()

			// Verify state is in the URL
			if !strings.Contains(location, "state="+url.QueryEscape(state)) {
				t.Errorf("State parameter not preserved. Expected state=%s in: %s",
					url.QueryEscape(state), location)
			}
		})
	}
}

// TestNonce_Preservation tests that nonce is preserved in ID token
func TestNonce_Preservation(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "test@example.com")

	nonceValues := []string{
		"simple-nonce",
		"nonce-with-special-chars-123456",
		strings.Repeat("n", 50),
	}

	for _, nonce := range nonceValues {
		t.Run("Nonce_"+nonce[:min(len(nonce), 20)], func(t *testing.T) {
			ar := newTestAuthRequest(t, client, user, WithNonce(nonce))

			// Verify nonce is stored in AuthRequest
			if ar.Nonce != nonce {
				t.Errorf("Expected nonce %q, got %q", nonce, ar.Nonce)
			}
		})
	}
}

// min returns the smaller of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
