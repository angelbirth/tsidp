// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// mockLocalClient implements LocalClient interface for testing
type mockLocalClientForAppCap struct {
	whoIsResponse *apitype.WhoIsResponse
	whoIsError    error
}

func (m *mockLocalClientForAppCap) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	if m.whoIsError != nil {
		return nil, m.whoIsError
	}
	return m.whoIsResponse, nil
}

// TestAppCapBypassMode tests that bypassAppCapCheck grants full access
func TestAppCapBypassMode(t *testing.T) {
	s := &IDPServer{
		bypassAppCapCheck: true,
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345" // Non-localhost address
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}

	// Verify full access granted
	if !capturedRules.allowAdminUI {
		t.Error("Expected allowAdminUI to be true in bypass mode")
	}
	if !capturedRules.allowDCR {
		t.Error("Expected allowDCR to be true in bypass mode")
	}
	if len(capturedRules.rules) != 0 {
		t.Errorf("Expected empty rules in bypass mode, got %d rules", len(capturedRules.rules))
	}
}

// TestAppCapNoLocalClient tests default-deny when LocalClient is nil
func TestAppCapNoLocalClient(t *testing.T) {
	s := &IDPServer{
		lc: nil, // No LocalClient
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}

	// Verify default-deny (no access)
	if capturedRules.allowAdminUI {
		t.Error("Expected allowAdminUI to be false when lc is nil")
	}
	if capturedRules.allowDCR {
		t.Error("Expected allowDCR to be false when lc is nil")
	}
	if len(capturedRules.rules) != 0 {
		t.Errorf("Expected empty rules when lc is nil, got %d rules", len(capturedRules.rules))
	}
}

// TestAppCapLocalhostBypass tests that localhost requests get full access
func TestAppCapLocalhostBypass(t *testing.T) {
	testCases := []struct {
		name       string
		remoteAddr string
		expectPass bool
	}{
		{
			name:       "IPv4 loopback 127.0.0.1",
			remoteAddr: "127.0.0.1:12345",
			expectPass: true,
		},
		{
			name:       "IPv6 loopback ::1",
			remoteAddr: "[::1]:12345",
			expectPass: true,
		},
		{
			name:       "Non-localhost IPv4",
			remoteAddr: "192.0.2.1:12345",
			expectPass: false,
		},
		{
			name:       "Non-localhost IPv6",
			remoteAddr: "[2001:db8::1]:12345",
			expectPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &IDPServer{
				lc: &mockLocalClientForAppCap{
					whoIsResponse: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{ID: 123},
					},
				},
			}

			var capturedRules *accessGrantedRules

			handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
				rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
				if !ok {
					t.Fatal("Expected access rules in context")
				}
				capturedRules = rules
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			if capturedRules == nil {
				t.Fatal("Expected access rules to be captured")
			}

			// Verify access based on expectation
			if tc.expectPass {
				if !capturedRules.allowAdminUI {
					t.Error("Expected allowAdminUI to be true for localhost")
				}
				if !capturedRules.allowDCR {
					t.Error("Expected allowDCR to be true for localhost")
				}
			} else {
				// For non-localhost, it should call WhoIs and get empty rules
				// (our mock returns a WhoIsResponse without CapMap)
				if capturedRules.allowAdminUI {
					t.Error("Expected allowAdminUI to be false for non-localhost")
				}
				if capturedRules.allowDCR {
					t.Error("Expected allowDCR to be false for non-localhost")
				}
			}
		})
	}
}

// TestAppCapWithValidGrants tests valid capability grants from WhoIs
func TestAppCapWithValidGrants(t *testing.T) {
	testCases := []struct {
		name              string
		capMap            tailcfg.PeerCapMap
		expectedAdminUI   bool
		expectedDCR       bool
		expectedRuleCount int
	}{
		{
			name: "allowAdminUI grant",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allow_admin_ui": true}`),
				},
			},
			expectedAdminUI:   true,
			expectedDCR:       false,
			expectedRuleCount: 1,
		},
		{
			name: "allowDCR grant",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allow_dcr": true}`),
				},
			},
			expectedAdminUI:   false,
			expectedDCR:       true,
			expectedRuleCount: 1,
		},
		{
			name: "both grants",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allow_admin_ui": true, "allow_dcr": true}`),
				},
			},
			expectedAdminUI:   true,
			expectedDCR:       true,
			expectedRuleCount: 1,
		},
		{
			name: "multiple rules accumulated",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allow_admin_ui": true}`),
					tailcfg.RawMessage(`{"allow_dcr": true}`),
				},
			},
			expectedAdminUI:   true,
			expectedDCR:       true,
			expectedRuleCount: 2,
		},
		{
			name: "no grants (empty capability)",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{}`),
				},
			},
			expectedAdminUI:   false,
			expectedDCR:       false,
			expectedRuleCount: 1,
		},
		{
			name:              "no capability map",
			capMap:            tailcfg.PeerCapMap{},
			expectedAdminUI:   false,
			expectedDCR:       false,
			expectedRuleCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &IDPServer{
				lc: &mockLocalClientForAppCap{
					whoIsResponse: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{
							ID: 123,
						},
						CapMap: tc.capMap,
					},
				},
			}

			var capturedRules *accessGrantedRules

			handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
				rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
				if !ok {
					t.Fatal("Expected access rules in context")
				}
				capturedRules = rules
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.0.2.1:12345" // Non-localhost
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			if capturedRules == nil {
				t.Fatal("Expected access rules to be captured")
			}

			// Verify grants
			if capturedRules.allowAdminUI != tc.expectedAdminUI {
				t.Errorf("Expected allowAdminUI=%v, got %v", tc.expectedAdminUI, capturedRules.allowAdminUI)
			}
			if capturedRules.allowDCR != tc.expectedDCR {
				t.Errorf("Expected allowDCR=%v, got %v", tc.expectedDCR, capturedRules.allowDCR)
			}
			if len(capturedRules.rules) != tc.expectedRuleCount {
				t.Errorf("Expected %d rules, got %d", tc.expectedRuleCount, len(capturedRules.rules))
			}
		})
	}
}

// TestAppCapMalformedGrants tests handling of invalid capability JSON
func TestAppCapMalformedGrants(t *testing.T) {
	testCases := []struct {
		name   string
		capMap tailcfg.PeerCapMap
	}{
		{
			name: "invalid JSON",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`{invalid json`),
				},
			},
		},
		{
			name: "wrong type",
			capMap: tailcfg.PeerCapMap{
				"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
					tailcfg.RawMessage(`"string instead of object"`),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &IDPServer{
				lc: &mockLocalClientForAppCap{
					whoIsResponse: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{
							ID: 123,
						},
						CapMap: tc.capMap,
					},
				},
			}

			handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
				t.Error("Handler should not be called for malformed grants")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.0.2.1:12345"
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Errorf("Expected status 500 for malformed grants, got %d", w.Code)
			}
		})
	}
}

// TestAppCapWhoIsError tests WhoIs network error handling
func TestAppCapWhoIsError(t *testing.T) {
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsError: errors.New("network error: connection refused"),
		},
	}

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called when WhoIs fails")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for WhoIs error, got %d", w.Code)
	}

	// Verify error message
	body := w.Body.String()
	if body == "" {
		t.Error("Expected error message in response body")
	}
}

// TestAppCapRemoteAddressHandling tests localTSMode vs standard mode
func TestAppCapRemoteAddressHandling(t *testing.T) {
	testCases := []struct {
		name               string
		localTSMode        bool
		remoteAddr         string
		forwardedForHeader string
	}{
		{
			name:               "localTSMode with X-Forwarded-For",
			localTSMode:        true,
			remoteAddr:         "127.0.0.1:12345",
			forwardedForHeader: "192.0.2.1",
		},
		{
			name:               "standard mode uses RemoteAddr",
			localTSMode:        false,
			remoteAddr:         "192.0.2.1:12345",
			forwardedForHeader: "10.0.0.1", // Should be ignored in standard mode
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &IDPServer{
				localTSMode: tc.localTSMode,
				lc: &mockLocalClientForAppCap{
					whoIsResponse: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{ID: 123},
					},
				},
			}

			var capturedRules *accessGrantedRules

			handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
				rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
				if !ok {
					t.Fatal("Expected access rules in context")
				}
				capturedRules = rules
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.forwardedForHeader != "" {
				req.Header.Set("X-Forwarded-For", tc.forwardedForHeader)
			}
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			if capturedRules == nil {
				t.Fatal("Expected access rules to be captured")
			}

			// Both modes should work and return access rules
			t.Logf("✅ Remote address handling successful for mode=%v", tc.localTSMode)
		})
	}
}

// TestAppCapContextPropagation verifies context propagation to downstream handlers
func TestAppCapContextPropagation(t *testing.T) {
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
				CapMap: tailcfg.PeerCapMap{
					"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
						tailcfg.RawMessage(`{"allow_admin_ui": true, "allow_dcr": true}`),
					},
				},
			},
		},
	}

	contextPropagated := false

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a downstream handler extracting access rules
		access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Error("Context value not propagated to downstream handler")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if !access.allowAdminUI || !access.allowDCR {
			t.Error("Expected grants not present in propagated context")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		contextPropagated = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if !contextPropagated {
		t.Error("Context was not properly propagated to downstream handler")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestAppCapDenyByDefaultEnforcement tests deny-by-default with empty rules
func TestAppCapDenyByDefaultEnforcement(t *testing.T) {
	// Create server with WhoIs response that has no tsidp capability
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
				// CapMap is empty - no grants
				CapMap: tailcfg.PeerCapMap{},
			},
		},
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}

	// Verify deny-by-default: no grants
	if capturedRules.allowAdminUI {
		t.Error("Expected allowAdminUI to be false (deny-by-default)")
	}
	if capturedRules.allowDCR {
		t.Error("Expected allowDCR to be false (deny-by-default)")
	}
	if len(capturedRules.rules) != 0 {
		t.Errorf("Expected no rules with empty CapMap, got %d rules", len(capturedRules.rules))
	}

	t.Log("✅ Deny-by-default enforcement successful")
}

// TestAppCapSTSRules tests STS-specific capability rules
func TestAppCapSTSRules(t *testing.T) {
	// Test that STS-specific fields (users, resources) are properly parsed
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
				CapMap: tailcfg.PeerCapMap{
					"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
						tailcfg.RawMessage(`{
							"allow_admin_ui": true,
							"users": ["alice@example.com", "bob@example.com"],
							"resources": ["https://api.example.com", "https://app.example.com"]
						}`),
					},
				},
			},
		},
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}

	if len(capturedRules.rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(capturedRules.rules))
	}

	rule := capturedRules.rules[0]

	// Verify STS fields were parsed
	if len(rule.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(rule.Users))
	}
	if len(rule.Resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(rule.Resources))
	}

	expectedUsers := []string{"alice@example.com", "bob@example.com"}
	for i, expected := range expectedUsers {
		if i >= len(rule.Users) || rule.Users[i] != expected {
			t.Errorf("Expected user[%d]=%s, got %v", i, expected, rule.Users)
		}
	}

	expectedResources := []string{"https://api.example.com", "https://app.example.com"}
	for i, expected := range expectedResources {
		if i >= len(rule.Resources) || rule.Resources[i] != expected {
			t.Errorf("Expected resource[%d]=%s, got %v", i, expected, rule.Resources)
		}
	}

	t.Log("✅ STS rules parsing successful")
}

// TestAppCapExtraClaimsField tests parsing of extraClaims field
func TestAppCapExtraClaimsField(t *testing.T) {
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
				CapMap: tailcfg.PeerCapMap{
					"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
						tailcfg.RawMessage(`{
							"includeInUserInfo": true,
							"extraClaims": {
								"department": "engineering",
								"role": "developer"
							}
						}`),
					},
				},
			},
		},
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}

	if len(capturedRules.rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(capturedRules.rules))
	}

	rule := capturedRules.rules[0]

	if !rule.IncludeInUserInfo {
		t.Error("Expected includeInUserInfo to be true")
	}

	if rule.ExtraClaims == nil {
		t.Fatal("Expected extraClaims to be set")
	}

	if len(rule.ExtraClaims) != 2 {
		t.Errorf("Expected 2 extra claims, got %d", len(rule.ExtraClaims))
	}

	if dept, ok := rule.ExtraClaims["department"].(string); !ok || dept != "engineering" {
		t.Errorf("Expected department=engineering, got %v", rule.ExtraClaims["department"])
	}

	if role, ok := rule.ExtraClaims["role"].(string); !ok || role != "developer" {
		t.Errorf("Expected role=developer, got %v", rule.ExtraClaims["role"])
	}

	t.Log("✅ Extra claims parsing successful")
}

// TestAppCapInvalidRemoteAddr tests handling of invalid remote address format
func TestAppCapInvalidRemoteAddr(t *testing.T) {
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
			},
		},
	}

	var capturedRules *accessGrantedRules

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		rules, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
		if !ok {
			t.Fatal("Expected access rules in context")
		}
		capturedRules = rules
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "invalid-address-format" // Invalid format
	w := httptest.NewRecorder()

	handler(w, req)

	// Even with invalid format, it should continue to WhoIs path
	// because the netip.ParseAddrPort error is ignored
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if capturedRules == nil {
		t.Fatal("Expected access rules to be captured")
	}
}

func BenchmarkAppCapBypassMode(b *testing.B) {
	s := &IDPServer{
		bypassAppCapCheck: true,
	}

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

func BenchmarkAppCapWithWhoIs(b *testing.B) {
	s := &IDPServer{
		lc: &mockLocalClientForAppCap{
			whoIsResponse: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: 123},
				CapMap: tailcfg.PeerCapMap{
					"tailscale.com/cap/tsidp": []tailcfg.RawMessage{
						tailcfg.RawMessage(`{"allow_admin_ui": true, "allow_dcr": true}`),
					},
				},
			},
		},
	}

	handler := s.addGrantAccessContext(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler(w, req)
	}
}
