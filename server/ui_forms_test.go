package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestUIHandleNewClientGET tests the GET request to render new client form
func TestUIHandleNewClientGET(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/new", nil)
	w := httptest.NewRecorder()

	s.handleNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify form elements are present
	if !strings.Contains(bodyStr, "name") {
		t.Error("Form should contain name field")
	}
	if !strings.Contains(bodyStr, "redirect_uris") {
		t.Error("Form should contain redirect_uris field")
	}
}

// TestUIHandleNewClientPOST tests creating a new client via POST
func TestUIHandleNewClientPOST(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("name", "Test Client")
	formData.Set("redirect_uris", "https://example.com/callback")

	req := httptest.NewRequest("POST", "/new", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify success message
	if !strings.Contains(bodyStr, "Client created successfully") {
		t.Error("Response should contain success message")
	}

	// Verify client was created
	s.mu.Lock()
	clientCount := len(s.funnelClients)
	s.mu.Unlock()

	if clientCount != 1 {
		t.Errorf("Expected 1 client, got %d", clientCount)
	}
}

// TestUIHandleNewClientPOSTMultipleRedirectURIs tests creating client with multiple redirect URIs
func TestUIHandleNewClientPOSTMultipleRedirectURIs(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("name", "Multi-URI Client")
	formData.Set("redirect_uris", "https://example.com/callback\nhttps://example.com/callback2\nhttp://localhost:8080/callback")

	req := httptest.NewRequest("POST", "/new", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify client has 3 redirect URIs
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.funnelClients) != 1 {
		t.Fatalf("Expected 1 client, got %d", len(s.funnelClients))
	}

	for _, client := range s.funnelClients {
		if len(client.RedirectURIs) != 3 {
			t.Errorf("Expected 3 redirect URIs, got %d", len(client.RedirectURIs))
		}
	}
}

// TestUIHandleNewClientPOSTEmptyRedirectURIs tests error when no redirect URIs provided
func TestUIHandleNewClientPOSTEmptyRedirectURIs(t *testing.T) {
	s := newTestServer(t)

	formData := url.Values{}
	formData.Set("name", "No URI Client")
	formData.Set("redirect_uris", "")

	req := httptest.NewRequest("POST", "/new", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "At least one redirect URI is required") {
		t.Error("Should show error for missing redirect URIs")
	}

	// Verify no client was created
	s.mu.Lock()
	clientCount := len(s.funnelClients)
	s.mu.Unlock()

	if clientCount != 0 {
		t.Errorf("Expected 0 clients, got %d", clientCount)
	}
}

// TestUIHandleNewClientPOSTInvalidRedirectURI tests error for invalid redirect URI
func TestUIHandleNewClientPOSTInvalidRedirectURI(t *testing.T) {
	s := newTestServer(t)

	testCases := []struct {
		name        string
		redirectURI string
		errorText   string
	}{
		{
			name:        "javascript scheme",
			redirectURI: "javascript:alert('xss')",
			errorText:   "Invalid redirect URI",
		},
		{
			name:        "data scheme",
			redirectURI: "data:text/html,<script>alert('xss')</script>",
			errorText:   "Invalid redirect URI",
		},
		{
			name:        "http non-localhost",
			redirectURI: "http://example.com/callback",
			errorText:   "Invalid redirect URI",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formData := url.Values{}
			formData.Set("name", "Bad URI Client")
			formData.Set("redirect_uris", tc.redirectURI)

			req := httptest.NewRequest("POST", "/new", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleNewClient(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			if !strings.Contains(bodyStr, tc.errorText) {
				t.Errorf("Should show error for invalid URI, got: %s", bodyStr)
			}

			// Verify no client was created
			s.mu.Lock()
			clientCount := len(s.funnelClients)
			s.mu.Unlock()

			if clientCount != 0 {
				t.Errorf("Expected 0 clients, got %d", clientCount)
			}
		})
	}
}

// TestUIHandleNewClientInvalidMethod tests invalid HTTP method
func TestUIHandleNewClientInvalidMethod(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("PUT", "/new", nil)
	w := httptest.NewRecorder()

	s.handleNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

// TestUIHandleEditClientGET tests viewing the edit form
func TestUIHandleEditClientGET(t *testing.T) {
	s := newTestServer(t)

	// Create a client first
	clientID := "test-client-id"
	client := addTestClient(t, s, clientID, "test-secret")
	client.Name = "Edit Test Client"

	req := httptest.NewRequest("GET", "/edit/"+clientID, nil)
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify form contains client data
	if !strings.Contains(bodyStr, "Edit Test Client") {
		t.Error("Form should contain client name")
	}
	if !strings.Contains(bodyStr, "https://example.com/callback") {
		t.Error("Form should contain redirect URI")
	}
}

// TestUIHandleEditClientGETNotFound tests editing non-existent client
func TestUIHandleEditClientGETNotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/edit/nonexistent", nil)
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestUIHandleEditClientGETNoClientID tests missing client ID
func TestUIHandleEditClientGETNoClientID(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/edit/", nil)
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestUIHandleEditClientPOSTUpdate tests updating client via POST
func TestUIHandleEditClientPOSTUpdate(t *testing.T) {
	s := newTestServer(t)

	clientID := "update-test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.Name = "Original Name"
	client.RedirectURIs = []string{"https://example.com/callback"}

	formData := url.Values{}
	formData.Set("name", "Updated Name")
	formData.Set("redirect_uris", "https://example.com/callback\nhttps://example.com/new")

	req := httptest.NewRequest("POST", "/edit/"+clientID, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify client was updated
	s.mu.Lock()
	updatedClient := s.funnelClients[clientID]
	s.mu.Unlock()

	if updatedClient.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", updatedClient.Name)
	}
	if len(updatedClient.RedirectURIs) != 2 {
		t.Errorf("Expected 2 redirect URIs, got %d", len(updatedClient.RedirectURIs))
	}
}

// TestUIHandleEditClientPOSTDelete tests deleting client
func TestUIHandleEditClientPOSTDelete(t *testing.T) {
	s := newTestServer(t)

	clientID := "delete-test-client"
	addTestClient(t, s, clientID, "test-secret")

	formData := url.Values{}
	formData.Set("action", "delete")

	req := httptest.NewRequest("POST", "/edit/"+clientID, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should redirect to home
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", resp.StatusCode)
	}

	// Verify client was deleted
	s.mu.Lock()
	_, exists := s.funnelClients[clientID]
	s.mu.Unlock()

	if exists {
		t.Error("Client should have been deleted")
	}
}

// TestUIHandleEditClientPOSTRegenerateSecret tests regenerating client secret
func TestUIHandleEditClientPOSTRegenerateSecret(t *testing.T) {
	s := newTestServer(t)

	clientID := "secret-test-client"
	addTestClient(t, s, clientID, "original-secret")

	// Get original secret
	s.mu.Lock()
	originalSecret := s.funnelClients[clientID].Secret
	s.mu.Unlock()

	formData := url.Values{}
	formData.Set("action", "regenerate_secret")

	req := httptest.NewRequest("POST", "/edit/"+clientID, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify success message
	if !strings.Contains(bodyStr, "New client secret generated") {
		t.Error("Should show success message for secret regeneration")
	}

	// Verify secret was changed
	s.mu.Lock()
	newSecret := s.funnelClients[clientID].Secret
	s.mu.Unlock()

	if newSecret == originalSecret {
		t.Error("Secret should have been regenerated")
	}
	if newSecret == "" {
		t.Error("New secret should not be empty")
	}
}

// TestUIHandleEditClientPOSTInvalidMethod tests invalid HTTP method
func TestUIHandleEditClientInvalidMethod(t *testing.T) {
	s := newTestServer(t)

	clientID := "method-test-client"
	addTestClient(t, s, clientID, "test-secret")

	req := httptest.NewRequest("PATCH", "/edit/"+clientID, nil)
	w := httptest.NewRecorder()

	s.handleEditClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

// TestUIRenderClientForm tests the renderClientForm helper
func TestUIRenderClientForm(t *testing.T) {
	s := newTestServer(t)

	w := httptest.NewRecorder()
	data := clientDisplayData{
		Name:         "Test Client",
		RedirectURIs: []string{"https://example.com/callback"},
		IsNew:        true,
	}

	err := s.renderClientForm(w, data)
	if err != nil {
		t.Fatalf("renderClientForm failed: %v", err)
	}

	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Test Client") {
		t.Error("Rendered form should contain client name")
	}
}

// TestUIRenderFormError tests renderFormError helper
func TestUIRenderFormError(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	data := clientDisplayData{
		Name:  "Error Test",
		IsNew: true,
	}

	s.renderFormError(w, req, data, "Test error message")

	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Test error message") {
		t.Error("Rendered form should contain error message")
	}
}

// TestUIRenderFormSuccess tests renderFormSuccess helper
func TestUIRenderFormSuccess(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	data := clientDisplayData{
		Name:  "Success Test",
		IsNew: true,
	}

	s.renderFormSuccess(w, req, data, "Test success message")

	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Test success message") {
		t.Error("Rendered form should contain success message")
	}
}
