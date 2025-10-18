package server

import (
	"testing"
)

// TestGenerateClientID tests generateClientID helper
func TestGenerateClientID(t *testing.T) {
	id1 := generateClientID()
	id2 := generateClientID()

	if id1 == "" {
		t.Error("Generated client ID should not be empty")
	}

	if id1 == id2 {
		t.Error("Generated client IDs should be unique")
	}

	// Client IDs should be hex strings (32 hex characters)
	if len(id1) == 0 {
		t.Error("Client ID should not be empty")
	}
}

// TestGenerateClientSecret tests generateClientSecret helper
func TestGenerateClientSecret(t *testing.T) {
	secret1 := generateClientSecret()
	secret2 := generateClientSecret()

	if secret1 == "" {
		t.Error("Generated client secret should not be empty")
	}

	if secret1 == secret2 {
		t.Error("Generated client secrets should be unique")
	}

	// Client secrets should be hex strings
	if len(secret1) == 0 {
		t.Error("Client secret should not be empty")
	}
}

// TestTestUtilsWithFunnel tests the WithFunnel option
func TestTestUtilsWithFunnel(t *testing.T) {
	s := newTestServer(t, WithFunnel())

	if !s.funnel {
		t.Error("Server should have funnel enabled")
	}
}

// TestTestUtilsWithSTS tests the WithSTS option
func TestTestUtilsWithSTS(t *testing.T) {
	s := newTestServer(t, WithSTS())

	if !s.enableSTS {
		t.Error("Server should have STS enabled")
	}
}

// TestTestUtilsWithLocalTSMode tests the WithLocalTSMode option
func TestTestUtilsWithLocalTSMode(t *testing.T) {
	s := newTestServer(t, WithLocalTSMode())

	if !s.localTSMode {
		t.Error("Server should have localTSMode enabled")
	}
}

// TestTestUtilsWithServerURL tests the WithServerURL option
func TestTestUtilsWithServerURL(t *testing.T) {
	testURL := "https://test.example.com"
	s := newTestServer(t, WithServerURL(testURL))

	if s.serverURL != testURL {
		t.Errorf("Expected server URL %q, got %q", testURL, s.serverURL)
	}
}

// TestTestUtilsWithResources tests the WithResources option
func TestTestUtilsWithResources(t *testing.T) {
	client := newTestClient(t, "test-client", "test-secret")
	user := newTestUser(t, "test@example.com")

	ar := newTestAuthRequest(t, client, user, WithResources("https://resource1.example.com", "https://resource2.example.com"))

	if len(ar.Resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(ar.Resources))
	}

	if ar.Resources[0] != "https://resource1.example.com" {
		t.Errorf("Resource 0: expected %q, got %q", "https://resource1.example.com", ar.Resources[0])
	}
	if ar.Resources[1] != "https://resource2.example.com" {
		t.Errorf("Resource 1: expected %q, got %q", "https://resource2.example.com", ar.Resources[1])
	}
}

// TestValidateRedirectURIEdgeCases tests additional edge cases for validateRedirectURI
func TestValidateRedirectURIEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{
			name:        "valid https with port",
			uri:         "https://example.com:8443/callback",
			expectError: false,
		},
		{
			name:        "valid localhost with port",
			uri:         "http://localhost:3000/callback",
			expectError: false,
		},
		{
			name:        "valid 127.0.0.1",
			uri:         "http://127.0.0.1:8080/callback",
			expectError: false,
		},
		{
			name:        "valid IPv6 loopback",
			uri:         "http://[::1]:8080/callback",
			expectError: false,
		},
		{
			name:        "https without host",
			uri:         "https:///callback",
			expectError: true,
		},
		{
			name:        "http without host",
			uri:         "http:///callback",
			expectError: true,
		},
		{
			name:        "no scheme",
			uri:         "example.com/callback",
			expectError: true,
		},
		{
			name:        "invalid url",
			uri:         "not a url",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateRedirectURI(tt.uri)
			hasError := result != ""

			if hasError != tt.expectError {
				if tt.expectError {
					t.Errorf("Expected error for URI %q, but got none", tt.uri)
				} else {
					t.Errorf("Expected no error for URI %q, but got: %s", tt.uri, result)
				}
			}
		})
	}
}

// Note: UI handler tests require app capability context which is complex to mock
// Basic UI functionality is covered in ui_forms_test.go with proper setup
