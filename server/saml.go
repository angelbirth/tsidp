// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAMLServiceProvider represents a registered Service Provider
type SAMLServiceProvider struct {
	EntityID string   `json:"entity_id"` // Unique SP identifier
	Name     string   `json:"name"`      // Display name for admin UI
	ACSURLs  []string `json:"acs_urls"`  // Allowed ACS URLs
}

const samlServiceProvidersFile = "saml-service-providers.json"

// storeSAMLServiceProvidersLocked persists the SP registry to disk
// Must be called with s.mu held
func (s *IDPServer) storeSAMLServiceProvidersLocked() error {
	if s.stateDir == "" {
		return nil // No persistence in ephemeral mode
	}

	path := filepath.Join(s.stateDir, samlServiceProvidersFile)

	// Convert map to array for storage
	spArray := make([]*SAMLServiceProvider, 0, len(s.samlServiceProviders))
	for _, sp := range s.samlServiceProviders {
		spArray = append(spArray, sp)
	}

	data, err := json.MarshalIndent(spArray, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SAML SPs: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write SAML SPs: %w", err)
	}

	return nil
}

// loadSAMLServiceProviders loads the SP registry from disk
func loadSAMLServiceProviders(stateDir string) (map[string]*SAMLServiceProvider, error) {
	sps := make(map[string]*SAMLServiceProvider)

	if stateDir == "" {
		return sps, nil // No persistence in ephemeral mode
	}

	path := filepath.Join(stateDir, samlServiceProvidersFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return sps, nil // Fresh install, no SPs registered yet
	}
	if err != nil {
		return nil, fmt.Errorf("read SAML SPs: %w", err)
	}

	// Unmarshal from array
	var spArray []*SAMLServiceProvider
	if err := json.Unmarshal(data, &spArray); err != nil {
		return nil, fmt.Errorf("unmarshal SAML SPs: %w", err)
	}

	// Convert array to map keyed by EntityID
	for _, sp := range spArray {
		sps[sp.EntityID] = sp
	}

	return sps, nil
}

// generateSAMLID generates a random ID for SAML entities
func generateSAMLID() string {
	idBytes := make([]byte, 20)
	if _, err := rand.Read(idBytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	return "id-" + hex.EncodeToString(idBytes)
}

// samlCertificate returns the X.509 certificate and private key for SAML signing.
// It generates a self-signed certificate from the OIDC private key and caches it on disk.
func (s *IDPServer) samlCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	sk, err := s.oidcPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	// Check if certificate already exists
	certPath := "saml-cert.pem"
	if s.stateDir != "" {
		certPath = filepath.Join(s.stateDir, "saml-cert.pem")
	}
	certBytes, err := os.ReadFile(certPath)
	if err == nil {
		// Parse existing certificate
		block, _ := pem.Decode(certBytes)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && time.Now().Before(cert.NotAfter) {
				return cert, sk.Key, nil
			}
		}
	}

	// Generate new self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   s.hostname,
			Organization: []string{"Tailscale IDP"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &sk.Key.PublicKey, sk.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save certificate to disk
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	return cert, sk.Key, nil
}

// serveSAMLMetadata handles the SAML metadata endpoint (GET /saml/metadata)
func (s *IDPServer) serveSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}

	cert, key, err := s.samlCertificate()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to get SAML certificate", err)
		return
	}

	// Create the Identity Provider configuration
	metadataURL, _ := url.Parse(s.serverURL + "/saml/metadata")
	ssoURL, _ := url.Parse(s.serverURL + "/saml/sso")

	idp := saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: *metadataURL,
		SSOURL:      *ssoURL,
	}

	metadata := idp.Metadata()

	// Marshal to XML
	xmlBytes, err := xml.Marshal(metadata)
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to marshal metadata", err)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(xmlBytes)
}

// serveSAMLSSO handles the SAML Single Sign-On endpoint (GET/POST /saml/sso)
func (s *IDPServer) serveSAMLSSO(w http.ResponseWriter, r *http.Request) {
	// Block Funnel requests - SAML SSO requires Tailnet access for WhoIs
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied,
			"SAML SSO not allowed over funnel", nil)
		return
	}

	// Extract SAMLRequest parameter
	var samlRequestParam string
	var relayState string

	switch r.Method {
	case http.MethodGet:
		// HTTP-Redirect binding
		samlRequestParam = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	case http.MethodPost:
		// HTTP-POST binding
		if err := r.ParseForm(); err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to parse form", err)
			return
		}
		samlRequestParam = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	default:
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}

	if samlRequestParam == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "missing SAMLRequest parameter", nil)
		return
	}

	// Decode and parse AuthnRequest
	authnRequest, err := s.parseAuthnRequest(samlRequestParam)
	if err != nil {
		slog.Error("failed to parse AuthnRequest", slog.Any("error", err))
		// For parse failures, we don't have enough info to send a proper SAML error
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid SAMLRequest", err)
		return
	}

	// Validate AuthnRequest
	if authnRequest.AssertionConsumerServiceURL == "" {
		s.sendSAMLError(w, r, "", authnRequest.ID, relayState,
			"urn:oasis:names:tc:SAML:2.0:status:Responder",
			"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
			"missing AssertionConsumerServiceURL")
		return
	}

	// Extract SP Entity ID from AuthnRequest
	var spEntityID string
	if authnRequest.Issuer != nil {
		spEntityID = authnRequest.Issuer.Value
	}
	if spEntityID == "" {
		s.sendSAMLError(w, r, authnRequest.AssertionConsumerServiceURL, authnRequest.ID, relayState,
			"urn:oasis:names:tc:SAML:2.0:status:Requester",
			"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
			"missing issuer")
		return
	}

	// SP verification (can be disabled for development)
	if !s.disableSAMLSPVerification {
		// Lookup SP in registry
		s.mu.Lock()
		sp, registered := s.samlServiceProviders[spEntityID]
		s.mu.Unlock()

		if !registered {
			slog.Warn("SAML SSO: unregistered SP attempted authentication",
				"entity_id", spEntityID,
				"remote_addr", r.RemoteAddr)
			s.sendSAMLError(w, r, authnRequest.AssertionConsumerServiceURL,
				authnRequest.ID, relayState,
				"urn:oasis:names:tc:SAML:2.0:status:Responder",
				"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
				"Service Provider not registered")
			return
		}

		// Validate ACS URL matches registered URLs
		acsURL := authnRequest.AssertionConsumerServiceURL
		validACS := false
		for _, registeredACS := range sp.ACSURLs {
			if acsURL == registeredACS {
				validACS = true
				break
			}
		}

		if !validACS {
			slog.Warn("SAML SSO: ACS URL mismatch",
				"entity_id", spEntityID,
				"requested_acs", acsURL,
				"registered_acs", sp.ACSURLs,
				"remote_addr", r.RemoteAddr)
			s.sendSAMLError(w, r, acsURL, authnRequest.ID, relayState,
				"urn:oasis:names:tc:SAML:2.0:status:Responder",
				"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
				"AssertionConsumerServiceURL not registered for this SP")
			return
		}

		slog.Info("SAML SSO: validated SP",
			"entity_id", spEntityID,
			"sp_name", sp.Name,
			"acs_url", acsURL)
	} else {
		slog.Warn("SAML SSO: SP verification disabled (development mode)")
	}

	// Identify user via Tailscale WhoIs
	var remoteAddr string
	if s.localTSMode {
		remoteAddr = r.Header.Get("X-Forwarded-For")
	} else {
		remoteAddr = r.RemoteAddr
	}

	who, err := s.lc.WhoIs(r.Context(), remoteAddr)
	if err != nil {
		slog.Error("WhoIs failed", slog.Any("error", err))
		s.sendSAMLError(w, r, authnRequest.AssertionConsumerServiceURL, authnRequest.ID, relayState,
			"urn:oasis:names:tc:SAML:2.0:status:Responder",
			"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
			"authentication failed")
		return
	}

	// Generate SAML Response
	if err := s.sendSAMLResponse(w, authnRequest, who.UserProfile.LoginName, spEntityID, relayState); err != nil {
		slog.Error("failed to send SAML response", slog.Any("error", err))
		s.sendSAMLError(w, r, authnRequest.AssertionConsumerServiceURL, authnRequest.ID, relayState,
			"urn:oasis:names:tc:SAML:2.0:status:Responder",
			"",
			"failed to generate response")
	} else {
		n := who.Node.View()
		slog.Info("successful SAML sso",
			slog.String("for", who.UserProfile.LoginName),
			slog.String("uid", n.User().String()),
			slog.String("spEntityID", spEntityID),
			slog.String("relayState", relayState),
		)

	}
}

// parseAuthnRequest decodes and parses a SAML AuthnRequest
func (s *IDPServer) parseAuthnRequest(samlRequestParam string) (*saml.AuthnRequest, error) {
	// Base64 decode
	compressedData, err := base64.StdEncoding.DecodeString(samlRequestParam)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	// Inflate (decompress)
	reader := flate.NewReader(bytes.NewReader(compressedData))
	defer reader.Close()

	xmlData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	// Parse XML
	var authnRequest saml.AuthnRequest
	if err := xml.Unmarshal(xmlData, &authnRequest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AuthnRequest: %w", err)
	}

	return &authnRequest, nil
}

// sendSAMLResponse generates and sends a signed SAML Response
func (s *IDPServer) sendSAMLResponse(w http.ResponseWriter, authnRequest *saml.AuthnRequest, email, spEntityID, relayState string) error {
	cert, key, err := s.samlCertificate()
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	entityID := s.serverURL + "/saml"
	now := time.Now()
	assertionID := generateSAMLID()
	responseID := generateSAMLID()

	// Build Assertion element
	assertionDoc := etree.NewDocument()
	assertionEl := assertionDoc.CreateElement("saml:Assertion")
	assertionEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertionEl.CreateAttr("ID", assertionID)
	assertionEl.CreateAttr("Version", "2.0")
	assertionEl.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))

	// Issuer
	issuer := assertionEl.CreateElement("saml:Issuer")
	issuer.SetText(entityID)

	// Subject
	subject := assertionEl.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText(email)

	subjectConfirmation := subject.CreateElement("saml:SubjectConfirmation")
	subjectConfirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfirmationData := subjectConfirmation.CreateElement("saml:SubjectConfirmationData")
	subjectConfirmationData.CreateAttr("InResponseTo", authnRequest.ID)
	subjectConfirmationData.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).UTC().Format(time.RFC3339))
	subjectConfirmationData.CreateAttr("Recipient", authnRequest.AssertionConsumerServiceURL)

	// Conditions
	conditions := assertionEl.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", now.Add(-5*time.Minute).UTC().Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).UTC().Format(time.RFC3339))
	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(spEntityID)

	// AuthnStatement
	authnStatement := assertionEl.CreateElement("saml:AuthnStatement")
	authnStatement.CreateAttr("AuthnInstant", now.UTC().Format(time.RFC3339))
	authnContext := authnStatement.CreateElement("saml:AuthnContext")
	authnContextClassRef := authnContext.CreateElement("saml:AuthnContextClassRef")
	authnContextClassRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	// AttributeStatement
	attrStatement := assertionEl.CreateElement("saml:AttributeStatement")
	attr := attrStatement.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", "email")
	attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
	attrValue := attr.CreateElement("saml:AttributeValue")
	attrValue.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	attrValue.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	attrValue.CreateAttr("xsi:type", "xs:string")
	attrValue.SetText(email)

	// Sign the Assertion
	signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{
		PrivateKey:  key,
		Certificate: [][]byte{cert.Raw},
	})
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)

	signedAssertionEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Build Response element
	responseDoc := etree.NewDocument()
	responseEl := responseDoc.CreateElement("samlp:Response")
	responseEl.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	responseEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	responseEl.CreateAttr("ID", responseID)
	responseEl.CreateAttr("Version", "2.0")
	responseEl.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	responseEl.CreateAttr("Destination", authnRequest.AssertionConsumerServiceURL)
	responseEl.CreateAttr("InResponseTo", authnRequest.ID)

	// Response Issuer
	respIssuer := responseEl.CreateElement("saml:Issuer")
	respIssuer.SetText(entityID)

	// Status
	status := responseEl.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	// Add signed assertion to response
	responseEl.AddChild(signedAssertionEl)

	// Sign the Response
	signedResponseEl, err := signingContext.SignEnveloped(responseEl)
	if err != nil {
		return fmt.Errorf("failed to sign response: %w", err)
	}

	// Marshal to XML
	responseDoc.SetRoot(signedResponseEl)
	responseXML, err := responseDoc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Base64 encode
	responseB64 := base64.StdEncoding.EncodeToString(responseXML)

	// Send HTTP-POST form
	s.sendHTTPPostForm(w, authnRequest.AssertionConsumerServiceURL, responseB64, relayState)
	return nil
}

// sendSAMLError sends a SAML error response via HTTP-POST binding
func (s *IDPServer) sendSAMLError(w http.ResponseWriter, r *http.Request, acsURL, inResponseTo, relayState string, statusCode, subStatusCode string, statusMessage string) {
	// If we don't have an ACS URL, we can't send a SAML error
	if acsURL == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, statusMessage, nil)
		return
	}

	cert, key, err := s.samlCertificate()
	if err != nil {
		slog.Error("failed to get certificate for error response", slog.Any("error", err))
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to generate error response", err)
		return
	}

	entityID := s.serverURL + "/saml"
	now := time.Now()
	responseID := generateSAMLID()

	// Build error Response element
	responseDoc := etree.NewDocument()
	responseEl := responseDoc.CreateElement("samlp:Response")
	responseEl.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	responseEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	responseEl.CreateAttr("ID", responseID)
	responseEl.CreateAttr("Version", "2.0")
	responseEl.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	responseEl.CreateAttr("Destination", acsURL)
	if inResponseTo != "" {
		responseEl.CreateAttr("InResponseTo", inResponseTo)
	}

	// Response Issuer
	issuer := responseEl.CreateElement("saml:Issuer")
	issuer.SetText(entityID)

	// Status
	status := responseEl.CreateElement("samlp:Status")
	statusCodeEl := status.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", statusCode)

	// Add sub-status code if provided
	if subStatusCode != "" {
		subStatusCodeEl := statusCodeEl.CreateElement("samlp:StatusCode")
		subStatusCodeEl.CreateAttr("Value", subStatusCode)
	}

	// Add status message if provided
	if statusMessage != "" {
		statusMessageEl := status.CreateElement("samlp:StatusMessage")
		statusMessageEl.SetText(statusMessage)
	}

	// Sign the error response
	signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{
		PrivateKey:  key,
		Certificate: [][]byte{cert.Raw},
	})
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)

	signedResponseEl, err := signingContext.SignEnveloped(responseEl)
	if err != nil {
		slog.Error("failed to sign error response", slog.Any("error", err))
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to sign error response", err)
		return
	}

	// Marshal to XML
	responseDoc.SetRoot(signedResponseEl)
	responseXML, err := responseDoc.WriteToBytes()
	if err != nil {
		slog.Error("failed to marshal error response", slog.Any("error", err))
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to marshal error response", err)
		return
	}

	// Base64 encode
	responseB64 := base64.StdEncoding.EncodeToString(responseXML)

	// Send HTTP-POST form
	s.sendHTTPPostForm(w, acsURL, responseB64, relayState)
}

// sendHTTPPostForm sends an HTML form that auto-submits to the ACS URL
func (s *IDPServer) sendHTTPPostForm(w http.ResponseWriter, acsURL, samlResponse, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// We need to avoid HTML escaping of the base64-encoded SAML response
	// Build the HTML manually to ensure no escaping happens
	var html strings.Builder
	html.WriteString(`<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>SAML POST</title>
</head>
<body onload="document.forms[0].submit()">
	<noscript>
		<p>JavaScript is disabled. Click the button below to continue.</p>
	</noscript>
	<form method="post" action="`)
	html.WriteString(template.HTMLEscapeString(acsURL))
	html.WriteString(`">
		<input type="hidden" name="SAMLResponse" value="`)
	html.WriteString(samlResponse) // Don't escape base64 data
	html.WriteString(`">`)

	if relayState != "" {
		html.WriteString(`
		<input type="hidden" name="RelayState" value="`)
		html.WriteString(template.HTMLEscapeString(relayState))
		html.WriteString(`">`)
	}

	html.WriteString(`
		<noscript>
			<button type="submit">Continue</button>
		</noscript>
	</form>
</body>
</html>`)

	w.Write([]byte(html.String()))
}
