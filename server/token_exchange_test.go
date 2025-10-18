package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestServeTokenExchangeInvalidMethod tests non-POST requests
func TestServeTokenExchangeInvalidMethod(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/token_exchange", nil)
	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

// TestServeTokenExchangeMissingSubjectToken tests missing subject_token
func TestServeTokenExchangeMissingSubjectToken(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "subject_token is required") {
		t.Error("Error should mention subject_token is required")
	}
}

// TestServeTokenExchangeUnsupportedSubjectTokenType tests invalid subject_token_type
func TestServeTokenExchangeUnsupportedSubjectTokenType(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("subject_token", "test-token")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "unsupported subject_token_type") {
		t.Error("Error should mention unsupported subject_token_type")
	}
}

// TestServeTokenExchangeUnsupportedRequestedTokenType tests invalid requested_token_type
func TestServeTokenExchangeUnsupportedRequestedTokenType(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("subject_token", "test-token")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("requested_token_type", "urn:ietf:params:oauth:token-type:jwt")

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "unsupported requested_token_type") {
		t.Error("Error should mention unsupported requested_token_type")
	}
}

// TestServeTokenExchangeMissingAudience tests missing audience parameter
func TestServeTokenExchangeMissingAudience(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("subject_token", "test-token")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "audience is required") {
		t.Error("Error should mention audience is required")
	}
}

// TestServeTokenExchangeInvalidClientCredentials tests missing client auth
func TestServeTokenExchangeInvalidClientCredentials(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("subject_token", "test-token")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://example.com")

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "invalid client credentials") {
		t.Error("Error should mention invalid client credentials")
	}
}

// TestServeTokenExchangeInvalidSubjectToken tests non-existent subject token
func TestServeTokenExchangeInvalidSubjectToken(t *testing.T) {
	s := newTestServer(t)

	clientID := "exchange-client"
	secret := "exchange-secret"
	addTestClient(t, s, clientID, secret)

	formData := url.Values{}
	formData.Set("subject_token", "invalid-token")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "invalid subject token") {
		t.Error("Error should mention invalid subject token")
	}
}

// TestServeTokenExchangeExpiredSubjectToken tests expired subject token
func TestServeTokenExchangeExpiredSubjectToken(t *testing.T) {
	s := newTestServer(t)

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create expired auth request
	user := newTestUser(t, "test@example.com")
	ar := newTestAuthRequest(t, client, user, WithValidTill(time.Now().Add(-time.Hour)))
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token_exchange", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	s.serveTokenExchange(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "subject token expired") {
		t.Error("Error should mention subject token expired")
	}
}

// Note: Actor token tests require ACL capabilities to be set up properly
// These tests are complex and require mocking tailscale capabilities
// Basic token exchange validation is covered by the tests above
