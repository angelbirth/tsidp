package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestRedirectAuthError tests the redirectAuthError helper function
func TestRedirectAuthError(t *testing.T) {
	tests := []struct {
		name             string
		redirectURI      string
		errorCode        string
		errorDescription string
		state            string
		wantStatus       int
		wantLocation     bool
	}{
		{
			name:             "valid redirect with state",
			redirectURI:      "https://example.com/callback",
			errorCode:        ecAccessDenied,
			errorDescription: "user denied access",
			state:            "test-state-123",
			wantStatus:       http.StatusFound,
			wantLocation:     true,
		},
		{
			name:             "valid redirect without description",
			redirectURI:      "https://example.com/callback",
			errorCode:        ecInvalidRequest,
			errorDescription: "",
			state:            "test-state",
			wantStatus:       http.StatusFound,
			wantLocation:     true,
		},
		{
			name:             "valid redirect without state",
			redirectURI:      "https://example.com/callback",
			errorCode:        ecInvalidClient,
			errorDescription: "client not found",
			state:            "",
			wantStatus:       http.StatusFound,
			wantLocation:     true,
		},
		{
			name:             "invalid redirect URI",
			redirectURI:      "://invalid-uri",
			errorCode:        ecInvalidRequest,
			errorDescription: "bad request",
			state:            "state",
			wantStatus:       http.StatusBadRequest,
			wantLocation:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/authorize", nil)
			w := httptest.NewRecorder()

			redirectAuthError(w, req, tt.redirectURI, tt.errorCode, tt.errorDescription, tt.state)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantLocation {
				location := resp.Header.Get("Location")
				if location == "" {
					t.Error("Expected Location header, got none")
				}

				// Parse the location and verify error parameters
				u, err := url.Parse(location)
				if err != nil {
					t.Fatalf("Invalid location URL: %v", err)
				}

				if u.Query().Get("error") != tt.errorCode {
					t.Errorf("Expected error=%s, got %s", tt.errorCode, u.Query().Get("error"))
				}

				if tt.errorDescription != "" {
					if u.Query().Get("error_description") != tt.errorDescription {
						t.Errorf("Expected error_description=%s, got %s", tt.errorDescription, u.Query().Get("error_description"))
					}
				}

				if tt.state != "" {
					if u.Query().Get("state") != tt.state {
						t.Errorf("Expected state=%s, got %s", tt.state, u.Query().Get("state"))
					}
				}
			} else if !tt.wantLocation {
				location := resp.Header.Get("Location")
				if location != "" {
					t.Errorf("Expected no Location header, got %s", location)
				}
			}
		})
	}
}

// TestServeAuthorizeFunnelBlocked tests that funnel requests are blocked
func TestServeAuthorizeFunnelBlocked(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	addTestClient(t, s, clientID, "test-secret")

	// Simulate a funnel request by setting the Tailscale-Funnel-Request header
	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback&state=test", nil)
	req.Header.Set("Tailscale-Funnel-Request", "1")

	w := httptest.NewRecorder()
	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for funnel request, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "not allowed over funnel") {
		t.Error("Error message should mention funnel blocking")
	}
}

// TestServeAuthorizeMissingRedirectURI tests missing redirect_uri parameter
func TestServeAuthorizeMissingRedirectURI(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=test&state=test", nil)
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "redirect_uri") {
		t.Error("Error message should mention redirect_uri")
	}
}

// TestServeAuthorizeMissingClientID tests missing client_id parameter
func TestServeAuthorizeMissingClientID(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?redirect_uri=https://example.com/callback&state=test", nil)
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "client_id") {
		t.Error("Error message should mention client_id")
	}
}

// TestServeAuthorizeInvalidClientID tests non-existent client ID
func TestServeAuthorizeInvalidClientID(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=nonexistent&redirect_uri=https://example.com/callback&state=test", nil)
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "invalid client ID") {
		t.Error("Error message should mention invalid client ID")
	}
}

// TestServeAuthorizeRedirectURIMismatch tests redirect_uri not registered with client
func TestServeAuthorizeRedirectURIMismatch(t *testing.T) {
	s := newTestServer(t)

	clientID := "redirect-test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Try to use a different redirect URI
	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri=https://evil.com/callback&state=test", nil)
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "redirect_uri mismatch") {
		t.Error("Error message should mention redirect_uri mismatch")
	}
}

// Note: Tests for deeper authorize flow (invalid scope, PKCE) are covered in authorize_test.go
// These tests require mocking the WhoIs client, which authorize_test.go handles properly
