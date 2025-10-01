// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// TestSAML_GenerateID tests the SAML ID generation function
func TestSAML_GenerateID(t *testing.T) {
	id1 := generateSAMLID()
	id2 := generateSAMLID()

	if id1 == id2 {
		t.Error("generateSAMLID() should generate unique IDs")
	}

	if !strings.HasPrefix(id1, "id-") {
		t.Errorf("generateSAMLID() = %s, should start with 'id-'", id1)
	}

	if len(id1) < 10 {
		t.Errorf("generateSAMLID() = %s, too short", id1)
	}
}

// TestSAML_Certificate tests certificate generation and caching
func TestSAML_Certificate(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()

	s := &IDPServer{
		stateDir: tmpDir,
		hostname: "test.example.com",
	}

	// First call should generate certificate
	cert1, key1, err := s.samlCertificate()
	if err != nil {
		t.Fatalf("samlCertificate() error = %v", err)
	}

	if cert1 == nil {
		t.Fatal("certificate is nil")
	}

	if key1 == nil {
		t.Fatal("private key is nil")
	}

	// Check certificate was saved to disk
	certPath := filepath.Join(tmpDir, "saml-cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("certificate file not created at %s", certPath)
	}

	// Second call should load from cache
	cert2, _, err := s.samlCertificate()
	if err != nil {
		t.Fatalf("samlCertificate() cached error = %v", err)
	}

	// Should return same certificate
	if !cert1.Equal(cert2) {
		t.Error("cached certificate doesn't match original")
	}

	// Check certificate properties
	if cert1.Subject.CommonName != "test.example.com" {
		t.Errorf("certificate CN = %s, want test.example.com", cert1.Subject.CommonName)
	}

	if cert1.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("certificate missing DigitalSignature key usage")
	}
}

// TestSAML_Metadata tests the SAML metadata endpoint
func TestSAML_Metadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &IDPServer{
		serverURL: "https://idp.test.ts.net",
		stateDir:  tmpDir,
		hostname:  "idp.test.ts.net",
		enableSAML: true,
	}

	tests := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{
			name:       "GET request",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST request not allowed",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/saml/metadata", nil)
			rr := httptest.NewRecorder()

			s.serveSAMLMetadata(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				// Check content type
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/samlmetadata+xml" {
					t.Errorf("Content-Type = %s, want application/samlmetadata+xml", contentType)
				}

				// Parse the metadata XML
				var metadata saml.EntityDescriptor
				if err := xml.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
					t.Fatalf("failed to parse metadata XML: %v", err)
				}

				// Validate metadata structure
				if metadata.EntityID == "" {
					t.Error("metadata missing EntityID")
				}

				if len(metadata.IDPSSODescriptors) == 0 {
					t.Fatal("metadata missing IDPSSODescriptor")
				}

				descriptor := metadata.IDPSSODescriptors[0]

				// Check for SSO service
				if len(descriptor.SingleSignOnServices) == 0 {
					t.Error("metadata missing SingleSignOnService")
				}

				// Check for signing certificate
				if len(descriptor.KeyDescriptors) == 0 {
					t.Error("metadata missing KeyDescriptor")
				}
			}
		})
	}
}

// TestSAML_SSO_BlocksFunnel tests that SSO endpoint blocks Funnel requests
func TestSAML_SSO_BlocksFunnel(t *testing.T) {
	tmpDir := t.TempDir()

	s := &IDPServer{
		serverURL: "https://idp.test.ts.net",
		stateDir:  tmpDir,
		hostname:  "idp.test.ts.net",
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	req.Header.Set("Tailscale-Funnel-Request", "true")
	rr := httptest.NewRecorder()

	s.serveSAMLSSO(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Funnel request status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "not allowed over funnel") {
		t.Errorf("error message doesn't mention funnel: %s", body)
	}
}

// TestSAML_SSO_MissingRequest tests handling of missing SAMLRequest parameter
func TestSAML_SSO_MissingRequest(t *testing.T) {
	tmpDir := t.TempDir()

	s := &IDPServer{
		serverURL: "https://idp.test.ts.net",
		stateDir:  tmpDir,
		hostname:  "idp.test.ts.net",
	}

	tests := []struct {
		name   string
		method string
	}{
		{
			name:   "GET without SAMLRequest",
			method: http.MethodGet,
		},
		{
			name:   "POST without SAMLRequest",
			method: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/saml/sso", nil)
			rr := httptest.NewRecorder()

			s.serveSAMLSSO(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
		})
	}
}

// TestSAML_ParseAuthnRequest tests parsing of SAML AuthnRequests
func TestSAML_ParseAuthnRequest(t *testing.T) {
	s := &IDPServer{}

	// Create a sample AuthnRequest
	authnRequest := `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="id-test-request-123"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z"
    Destination="https://idp.test.ts.net/saml/sso"
    AssertionConsumerServiceURL="http://localhost:58080/saml/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>http://localhost:58080/saml</saml:Issuer>
</samlp:AuthnRequest>`

	// Compress the request
	var buf strings.Builder
	writer, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	writer.Write([]byte(authnRequest))
	writer.Close()

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString([]byte(buf.String()))

	// Parse it
	parsed, err := s.parseAuthnRequest(encoded)
	if err != nil {
		t.Fatalf("parseAuthnRequest() error = %v", err)
	}

	if parsed.ID != "id-test-request-123" {
		t.Errorf("ID = %s, want id-test-request-123", parsed.ID)
	}

	if parsed.AssertionConsumerServiceURL != "http://localhost:58080/saml/acs" {
		t.Errorf("ACS URL = %s, want http://localhost:58080/saml/acs", parsed.AssertionConsumerServiceURL)
	}

	if parsed.Issuer == nil || parsed.Issuer.Value != "http://localhost:58080/saml" {
		t.Error("Issuer not parsed correctly")
	}
}

// TestSAML_ParseAuthnRequest_Invalid tests handling of invalid requests
func TestSAML_ParseAuthnRequest_Invalid(t *testing.T) {
	s := &IDPServer{}

	tests := []struct {
		name    string
		request string
	}{
		{
			name:    "invalid base64",
			request: "not-valid-base64!!!",
		},
		{
			name:    "invalid XML",
			request: base64.StdEncoding.EncodeToString([]byte("not xml")),
		},
		{
			name:    "empty request",
			request: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.parseAuthnRequest(tt.request)
			if err == nil {
				t.Error("parseAuthnRequest() should return error for invalid input")
			}
		})
	}
}

// TestSAML_HTTPPostForm tests the HTTP POST form generation
func TestSAML_HTTPPostForm(t *testing.T) {
	s := &IDPServer{}

	rr := httptest.NewRecorder()
	acsURL := "http://localhost:58080/saml/acs"
	samlResponse := "base64encodedresponse"
	relayState := "test-relay-state"

	s.sendHTTPPostForm(rr, acsURL, samlResponse, relayState)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %s, want text/html", contentType)
	}

	body := rr.Body.String()

	// Check for required form elements
	requiredElements := []string{
		"<form",
		`action="` + acsURL + `"`,
		`name="SAMLResponse"`,
		`value="` + samlResponse + `"`,
		`name="RelayState"`,
		`value="` + relayState + `"`,
		"onload",
		"submit()",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(body, elem) {
			t.Errorf("form missing element: %s", elem)
		}
	}
}

// TestSAML_HTTPPostForm_NoRelayState tests form without RelayState
func TestSAML_HTTPPostForm_NoRelayState(t *testing.T) {
	s := &IDPServer{}

	rr := httptest.NewRecorder()
	acsURL := "http://localhost:58080/saml/acs"
	samlResponse := "base64encodedresponse"

	s.sendHTTPPostForm(rr, acsURL, samlResponse, "")

	body := rr.Body.String()

	// Should NOT have RelayState field when empty
	if strings.Contains(body, "RelayState") {
		t.Error("form should not include RelayState when empty")
	}
}

// TestSAML_ErrorResponse tests error response generation
func TestSAML_ErrorResponse(t *testing.T) {
	tmpDir := t.TempDir()

	s := &IDPServer{
		serverURL: "https://idp.test.ts.net",
		stateDir:  tmpDir,
		hostname:  "idp.test.ts.net",
	}

	tests := []struct {
		name           string
		acsURL         string
		inResponseTo   string
		relayState     string
		statusCode     string
		subStatusCode  string
		statusMessage  string
		wantHTTPStatus int
	}{
		{
			name:           "complete error",
			acsURL:         "http://localhost:58080/saml/acs",
			inResponseTo:   "id-request-123",
			relayState:     "test-state",
			statusCode:     "urn:oasis:names:tc:SAML:2.0:status:Responder",
			subStatusCode:  "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
			statusMessage:  "Authentication failed",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name:           "error without substatus",
			acsURL:         "http://localhost:58080/saml/acs",
			inResponseTo:   "id-request-456",
			relayState:     "",
			statusCode:     "urn:oasis:names:tc:SAML:2.0:status:Requester",
			subStatusCode:  "",
			statusMessage:  "Invalid request",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name:           "no ACS URL",
			acsURL:         "",
			inResponseTo:   "id-request-789",
			relayState:     "",
			statusCode:     "urn:oasis:names:tc:SAML:2.0:status:Responder",
			subStatusCode:  "",
			statusMessage:  "Missing ACS URL",
			wantHTTPStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
			rr := httptest.NewRecorder()

			s.sendSAMLError(rr, req, tt.acsURL, tt.inResponseTo, tt.relayState, tt.statusCode, tt.subStatusCode, tt.statusMessage)

			if rr.Code != tt.wantHTTPStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantHTTPStatus)
			}

			if tt.wantHTTPStatus == http.StatusOK {
				// Should return HTML form
				body := rr.Body.String()
				if !strings.Contains(body, "<form") {
					t.Error("response should contain HTML form")
				}

				if !strings.Contains(body, "SAMLResponse") {
					t.Error("response should contain SAMLResponse field")
				}

				// If RelayState provided, check it's in the form
				if tt.relayState != "" && !strings.Contains(body, tt.relayState) {
					t.Error("response should preserve RelayState")
				}
			}
		})
	}
}

// TestSAML_RouteRegistration tests that SAML routes are conditionally registered
func TestSAML_RouteRegistration(t *testing.T) {
	tests := []struct {
		name       string
		enableSAML bool
		wantRoutes bool
	}{
		{
			name:       "SAML enabled",
			enableSAML: true,
			wantRoutes: true,
		},
		{
			name:       "SAML disabled",
			enableSAML: false,
			wantRoutes: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:  "https://idp.test.ts.net",
				hostname:   "idp.test.ts.net",
				enableSAML: tt.enableSAML,
				stateDir:   t.TempDir(),
			}

			mux := s.newMux()

			// Test metadata endpoint
			metadataReq := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
			metadataRR := httptest.NewRecorder()
			mux.ServeHTTP(metadataRR, metadataReq)

			// Test SSO endpoint
			ssoReq := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
			ssoRR := httptest.NewRecorder()
			mux.ServeHTTP(ssoRR, ssoReq)

			if tt.wantRoutes {
				// Routes should exist - check they don't return 404
				if metadataRR.Code == http.StatusNotFound {
					t.Error("SAML metadata route should be registered but got 404")
				}
				if ssoRR.Code == http.StatusNotFound {
					t.Error("SAML SSO route should be registered but got 404")
				}
			} else {
				// Routes should not exist - will fall through to UI handler which returns 403 or 404
				// The important thing is they shouldn't succeed with a valid SAML response
				// Check that the response doesn't look like a SAML response
				if strings.Contains(metadataRR.Body.String(), "EntityDescriptor") {
					t.Error("SAML metadata route should not be registered but returned metadata")
				}
				if strings.Contains(ssoRR.Body.String(), "SAMLResponse") {
					t.Error("SAML SSO route should not be registered but returned SAML response")
				}
			}
		})
	}
}

// TestSAML_ResponseStructure tests that generated SAML responses have correct structure
func TestSAML_ResponseStructure(t *testing.T) {
	tmpDir := t.TempDir()

	s := &IDPServer{
		serverURL: "https://idp.test.ts.net",
		stateDir:  tmpDir,
		hostname:  "idp.test.ts.net",
	}

	// Create a mock AuthnRequest
	authnReq := &saml.AuthnRequest{
		ID:                            "id-test-123",
		AssertionConsumerServiceURL:   "http://localhost:58080/saml/acs",
		Destination:                   "https://idp.test.ts.net/saml/sso",
		Issuer: &saml.Issuer{
			Value: "http://localhost:58080/saml",
		},
	}

	email := "user@example.com"
	spEntityID := "http://localhost:58080/saml"
	relayState := "test-state"

	rr := httptest.NewRecorder()
	err := s.sendSAMLResponse(rr, authnReq, email, spEntityID, relayState)
	if err != nil {
		t.Fatalf("sendSAMLResponse() error = %v", err)
	}

	// Parse the HTML form response
	body := rr.Body.String()
	if !strings.Contains(body, "SAMLResponse") {
		t.Fatal("response doesn't contain SAMLResponse field")
	}

	// Extract the base64-encoded SAML response from the HTML
	// This is a simple extraction - in real tests you'd use proper HTML parsing
	startMarker := `name="SAMLResponse" value="`
	startIdx := strings.Index(body, startMarker)
	if startIdx == -1 {
		t.Fatalf("couldn't find SAMLResponse value in HTML: %s", body)
	}
	startIdx += len(startMarker)
	endIdx := strings.Index(body[startIdx:], `"`)
	if endIdx == -1 {
		t.Fatalf("couldn't find end of SAMLResponse value, body from start: %s", body[startIdx:startIdx+100])
	}
	encodedResponse := body[startIdx : startIdx+endIdx]

	// Trim any whitespace that might have been added
	encodedResponse = strings.TrimSpace(encodedResponse)

	// Debug: check for non-base64 characters
	if len(encodedResponse) > 403 {
		t.Logf("Character at position 403: %q (byte: %d)", encodedResponse[403], encodedResponse[403])
		t.Logf("Context around 403: %q", encodedResponse[395:min(410, len(encodedResponse))])
	}

	// Remove any newlines or carriage returns that might have been inserted
	encodedResponse = strings.ReplaceAll(encodedResponse, "\n", "")
	encodedResponse = strings.ReplaceAll(encodedResponse, "\r", "")

	// Decode and parse the SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		t.Fatalf("failed to decode SAMLResponse (len=%d, first 100 chars=%q): %v",
			len(encodedResponse),
			encodedResponse[:min(100, len(encodedResponse))],
			err)
	}

	// Parse XML
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decodedResponse); err != nil {
		t.Fatalf("failed to parse SAML response XML: %v", err)
	}

	// Check response structure
	root := doc.Root()
	if root == nil || root.Tag != "Response" {
		t.Error("root element should be Response")
	}

	// Check InResponseTo
	inResponseTo := root.SelectAttrValue("InResponseTo", "")
	if inResponseTo != authnReq.ID {
		t.Errorf("InResponseTo = %s, want %s", inResponseTo, authnReq.ID)
	}

	// Check for Assertion
	assertion := root.FindElement("//Assertion")
	if assertion == nil {
		t.Fatal("response missing Assertion")
	}

	// Check for Subject with NameID
	subject := assertion.FindElement("//Subject")
	if subject == nil {
		t.Fatal("assertion missing Subject")
	}

	nameID := subject.FindElement("//NameID")
	if nameID == nil {
		t.Fatal("subject missing NameID")
	}

	if nameID.Text() != email {
		t.Errorf("NameID = %s, want %s", nameID.Text(), email)
	}

	// Check for Audience
	audience := assertion.FindElement("//Audience")
	if audience == nil {
		t.Fatal("assertion missing Audience")
	}

	if audience.Text() != spEntityID {
		t.Errorf("Audience = %s, want %s", audience.Text(), spEntityID)
	}

	// Check for AttributeStatement
	attrStatement := assertion.FindElement("//AttributeStatement")
	if attrStatement == nil {
		t.Fatal("assertion missing AttributeStatement")
	}

	// Check for email attribute
	attrs := attrStatement.FindElements("//Attribute[@Name='email']")
	if len(attrs) == 0 {
		t.Fatal("assertion missing email attribute")
	}

	// Check for signatures
	responseSignature := root.FindElement("//Signature")
	if responseSignature == nil {
		t.Error("response missing Signature")
	}

	assertionSignature := assertion.FindElement("//Signature")
	if assertionSignature == nil {
		t.Error("assertion missing Signature")
	}
}
