package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
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

// TestServeTokenExchangeACLValidUserValidResource tests successful token exchange with matching ACL
func TestServeTokenExchangeACLValidUserValidResource(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with STS capability grant
	user := newTestUser(t, "alice@example.com")
	// Add capability grant: alice can access https://api.example.com
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify response contains access_token
	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := tokenResp["access_token"]; !ok {
		t.Error("Response should contain access_token")
	}
}

// TestServeTokenExchangeACLValidUserInvalidResource tests denial when resource not in ACL
func TestServeTokenExchangeACLValidUserInvalidResource(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with STS capability grant
	user := newTestUser(t, "alice@example.com")
	// Alice can only access api.example.com, NOT unauthorized-api.com
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://unauthorized-api.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "access denied for requested audience") {
		t.Error("Error should mention access denied for requested audience")
	}
}

// TestServeTokenExchangeACLInvalidUserValidResource tests denial when user not in ACL
func TestServeTokenExchangeACLInvalidUserValidResource(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user NOT in the ACL
	user := newTestUser(t, "bob@example.com")
	// ACL only allows alice, not bob
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "access denied for requested audience") {
		t.Error("Error should mention access denied for requested audience")
	}
}

// TestServeTokenExchangeACLWildcardUsers tests wildcard user access
func TestServeTokenExchangeACLWildcardUsers(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with wildcard STS capability grant
	user := newTestUser(t, "anyone@example.com")
	// Wildcard "*" allows all users
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["*"],
				"resources": ["https://public-api.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://public-api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 for wildcard user, got %d: %s", resp.StatusCode, string(body))
	}
}

// TestServeTokenExchangeACLWildcardResources tests wildcard resource access
func TestServeTokenExchangeACLWildcardResources(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with wildcard resource STS capability grant
	user := newTestUser(t, "alice@example.com")
	// Alice can access any resource (wildcard "*")
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["*"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://any-api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 for wildcard resource, got %d: %s", resp.StatusCode, string(body))
	}
}

// TestServeTokenExchangeACLMultipleAudiences tests token exchange with multiple audiences
func TestServeTokenExchangeACLMultipleAudiences(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with STS capability grant for multiple resources
	user := newTestUser(t, "alice@example.com")
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api1.example.com", "https://api2.example.com", "https://api3.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	// Request two audiences (RFC 8693 allows multiple)
	formData.Add("audience", "https://api1.example.com")
	formData.Add("audience", "https://api2.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 for multiple audiences, got %d: %s", resp.StatusCode, string(body))
	}
}

// TestServeTokenExchangeACLPartialAudienceMatch tests partial audience match (some allowed, some not)
func TestServeTokenExchangeACLPartialAudienceMatch(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with limited STS capability grant
	user := newTestUser(t, "alice@example.com")
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api1.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	// Request two audiences, only one is allowed
	formData.Add("audience", "https://api1.example.com")          // Allowed
	formData.Add("audience", "https://unauthorized-api.example.com") // NOT allowed
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should succeed with partial match (only allowed audiences returned)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 (partial match allowed), got %d: %s", resp.StatusCode, string(body))
	}
}

// TestServeTokenExchangeActorToken tests actor token chains for delegation (RFC 8693 Section 4.1)
func TestServeTokenExchangeActorToken(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create main user (subject)
	subjectUser := newTestUser(t, "alice@example.com")
	subjectUser.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api.example.com"]
			}`),
		},
	}

	// Create actor user (delegator)
	actorUser := newTestUser(t, "service@example.com")
	actorUser.Node.User = 999  // Different user ID

	arSubject := newTestAuthRequest(t, client, subjectUser)
	subjectToken := addTestAccessToken(t, s, arSubject)

	arActor := newTestAuthRequest(t, client, actorUser)
	actorToken := addTestAccessToken(t, s, arActor)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("actor_token", actorToken)
	formData.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 with actor token, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify the new access token was created
	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := tokenResp["access_token"]; !ok {
		t.Error("Response should contain access_token")
	}

	// Verify the token contains actor information (checked via introspection or token issuance)
	newAccessToken := tokenResp["access_token"].(string)

	s.mu.Lock()
	newAR, ok := s.accessToken[newAccessToken]
	s.mu.Unlock()

	if !ok {
		t.Fatal("New access token should exist")
	}

	if newAR.ActorInfo == nil {
		t.Error("New access token should have ActorInfo set")
	}

	if newAR.ActorInfo.Subject != "userid:999" {
		t.Errorf("Actor subject should be 'userid:999', got %s", newAR.ActorInfo.Subject)
	}
}

// TestServeTokenExchangeInvalidActorToken tests invalid actor token handling
func TestServeTokenExchangeInvalidActorToken(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	user := newTestUser(t, "alice@example.com")
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("actor_token", "invalid-actor-token")
	formData.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://api.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid actor token, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "invalid or expired actor_token") {
		t.Error("Error should mention invalid or expired actor_token")
	}
}

// TestServeTokenExchangeMultipleRules tests multiple ACL rules
func TestServeTokenExchangeMultipleRules(t *testing.T) {
	s := newTestServer(t, WithSTS())

	clientID := "exchange-client"
	secret := "exchange-secret"
	client := addTestClient(t, s, clientID, secret)

	// Create user with multiple STS rules
	user := newTestUser(t, "alice@example.com")
	user.CapMap = tailcfg.PeerCapMap{
		"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
			// Rule 1: Alice can access api1
			tailcfg.RawMessage(`{
				"users": ["alice@example.com"],
				"resources": ["https://api1.example.com"]
			}`),
			// Rule 2: All users can access public API
			tailcfg.RawMessage(`{
				"users": ["*"],
				"resources": ["https://public.example.com"]
			}`),
		},
	}

	ar := newTestAuthRequest(t, client, user)
	subjectToken := addTestAccessToken(t, s, ar)

	// Test accessing api1 (should work via rule 1)
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	formData.Set("audience", "https://api1.example.com")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		body, _ := io.ReadAll(w.Result().Body)
		t.Errorf("Expected status 200 for api1 via rule 1, got %d: %s", w.Result().StatusCode, string(body))
	}

	// Test accessing public API (should work via rule 2)
	formData.Set("audience", "https://public.example.com")
	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()

	s.ServeHTTP(w2, req2)

	if w2.Result().StatusCode != http.StatusOK {
		body, _ := io.ReadAll(w2.Result().Body)
		t.Errorf("Expected status 200 for public API via rule 2, got %d: %s", w2.Result().StatusCode, string(body))
	}
}
