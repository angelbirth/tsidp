// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command verifier-saml validates SAML 2.0 Identity Provider implementations.
//
// It performs automated testing of the SAML SSO flow, metadata validation,
// assertion verification, and signature checking to ensure compliance with
// SAML 2.0 specifications and security best practices.
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

var (
	idpURL         = flag.String("idp", "", "IdP base URL (required unless -idp-metadata-url is provided)")
	idpMetadataURL = flag.String("idp-metadata-url", "", "Direct URL to IdP metadata XML (overrides -idp)")
	acsPort        = flag.Int("acs-port", 58080, "Local ACS server port (default: 58080)")
	acsURL         = flag.String("acs-url", "", "Public-facing ACS URL (use for funnel urls)")
	spEntityID     = flag.String("sp-entity-id", "", "Service Provider entity ID (default: auto-generated)")
	skipSHA1       = flag.Bool("allow-sha1", false, "Allow SHA-1 signatures (not recommended)")
	verbose        = flag.Bool("v", false, "Verbose output")
)

type verificationResult struct {
	passed  bool
	message string
	level   string // "info", "warning", "error", "critical"
	detail  string
}

type verifier struct {
	idpURL     string
	acsPort    int
	spEntityID string
	acsURL     string

	metadata     *saml.EntityDescriptor
	certificates []*x509.Certificate
	requestID    string
	samlResponse []byte

	results      []verificationResult
	server       *http.Server
	responseChan chan []byte
}

func main() {
	flag.Parse()

	if *idpURL == "" && *idpMetadataURL == "" {
		fmt.Fprintf(os.Stderr, "Error: either -idp or -idp-metadata-url flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	v := &verifier{
		idpURL:       strings.TrimSuffix(*idpURL, "/"),
		acsPort:      *acsPort,
		results:      make([]verificationResult, 0),
		responseChan: make(chan []byte, 1),
	}

	if *spEntityID != "" {
		v.spEntityID = *spEntityID
	}

	printHeader("SAML 2.0 Identity Provider Verifier")
	printInfo("Testing IdP: %s", v.idpURL)
	fmt.Println()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		printWarning("\nReceived interrupt signal, shutting down...")
		cancel()
		if v.server != nil {
			v.server.Shutdown(context.Background())
		}
		os.Exit(1)
	}()

	// Execute verification steps
	if err := v.run(ctx); err != nil {
		printError("Verification failed: %v", err)
		os.Exit(1)
	}

	// Display results
	v.displayResults()
}

func (v *verifier) run(ctx context.Context) error {
	// Step 1: Fetch and validate IdP metadata
	printStep("Step 1: Fetching IdP metadata")
	if err := v.fetchMetadata(ctx); err != nil {
		return fmt.Errorf("metadata fetch failed: %w", err)
	}
	v.addResult(true, "Metadata fetched successfully", "info", "")

	// Step 2: Validate metadata structure and certificates
	printStep("Step 2: Validating metadata")
	if err := v.validateMetadata(); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	// Step 3: Start local ACS server
	printStep("Step 3: Starting local ACS server")
	if err := v.startACSServer(); err != nil {
		return fmt.Errorf("failed to start ACS server: %w", err)
	}
	defer v.stopACSServer()

	// Step 4: Generate AuthnRequest
	printStep("Step 4: Generating AuthnRequest")
	authURL, err := v.generateAuthnRequest()
	if err != nil {
		return fmt.Errorf("failed to generate AuthnRequest: %w", err)
	}
	v.addResult(true, "AuthnRequest generated", "info", "")

	// Step 5: Display authorization URL and wait for response
	printStep("Step 5: Waiting for user authentication")
	fmt.Println()
	printInfo("Please open this URL in your browser to authenticate:")
	fmt.Printf("\n%s%s%s\n\n", colorCyan, authURL, colorReset)
	printInfo("Waiting for SAML response (press Ctrl+C to cancel)...")

	select {
	case v.samlResponse = <-v.responseChan:
		printSuccess("SAML response received!")
	case <-ctx.Done():
		return fmt.Errorf("operation cancelled")
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timeout waiting for SAML response")
	}

	// Step 6: Parse SAML Response
	printStep("Step 6: Parsing SAML response")
	response, err := v.parseSAMLResponse()
	if err != nil {
		return fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Step 7: Validate Response
	printStep("Step 7: Validating SAML response and signatures")
	if err := v.validateResponse(response); err != nil {
		return fmt.Errorf("response validation failed: %w", err)
	}

	// Step 8: Validate Assertion
	printStep("Step 8: Validating assertion")
	if err := v.validateAssertion(response); err != nil {
		return fmt.Errorf("assertion validation failed: %w", err)
	}

	// Step 9: Extract and validate attributes
	printStep("Step 9: Extracting user attributes")
	if err := v.extractAttributes(response); err != nil {
		return fmt.Errorf("attribute extraction failed: %w", err)
	}

	return nil
}

func (v *verifier) fetchMetadata(ctx context.Context) error {
	var metadataURLs []string

	// If direct metadata URL provided, use it
	if *idpMetadataURL != "" {
		metadataURLs = []string{*idpMetadataURL}
	} else {
		// Try common metadata endpoint
		metadataURLs = []string{
			v.idpURL + "/saml/metadata",
		}
	}

	var lastErr error
	for _, metadataURL := range metadataURLs {
		if *verbose {
			printInfo("Trying: %s", metadataURL)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		// Parse metadata
		var metadata saml.EntityDescriptor
		if err := xml.Unmarshal(body, &metadata); err != nil {
			lastErr = fmt.Errorf("invalid XML: %w", err)
			continue
		}

		v.metadata = &metadata
		printSuccess("Found metadata at: %s", metadataURL)
		return nil
	}

	return fmt.Errorf("metadata not found (tried %d endpoints): %v", len(metadataURLs), lastErr)
}

func (v *verifier) validateMetadata() error {
	if v.metadata == nil {
		return fmt.Errorf("metadata is nil")
	}

	// Validate EntityDescriptor
	if v.metadata.EntityID == "" {
		v.addResult(false, "EntityID missing", "error", "EntityDescriptor must have entityID attribute")
		return fmt.Errorf("entityID is required")
	}
	v.addResult(true, fmt.Sprintf("EntityID: %s", v.metadata.EntityID), "info", "")

	// Validate IDPSSODescriptor
	if v.metadata.IDPSSODescriptors == nil || len(v.metadata.IDPSSODescriptors) == 0 {
		v.addResult(false, "IDPSSODescriptor missing", "error", "Metadata must contain IDPSSODescriptor")
		return fmt.Errorf("IDPSSODescriptor not found")
	}
	v.addResult(true, "IDPSSODescriptor found", "info", "")

	idpDesc := v.metadata.IDPSSODescriptors[0]

	// Validate SingleSignOnService endpoints
	if len(idpDesc.SingleSignOnServices) == 0 {
		v.addResult(false, "No SingleSignOnService endpoints", "error", "")
		return fmt.Errorf("no SingleSignOnService endpoints found")
	}

	// Check for HTTP-Redirect and HTTP-POST bindings
	hasRedirect := false
	hasPost := false
	for _, sso := range idpDesc.SingleSignOnServices {
		if strings.Contains(sso.Binding, "HTTP-Redirect") {
			hasRedirect = true
		}
		if strings.Contains(sso.Binding, "HTTP-POST") {
			hasPost = true
		}
	}

	if !hasRedirect {
		v.addResult(false, "HTTP-Redirect binding not supported", "warning", "SP-initiated SSO may not work")
	} else {
		v.addResult(true, "HTTP-Redirect binding supported", "info", "")
	}

	if !hasPost {
		v.addResult(false, "HTTP-POST binding not supported", "error", "Required for receiving responses")
		return fmt.Errorf("HTTP-POST binding required")
	} else {
		v.addResult(true, "HTTP-POST binding supported", "info", "")
	}

	// Extract and validate certificates
	if len(idpDesc.KeyDescriptors) == 0 {
		v.addResult(false, "No signing certificates found", "error", "")
		return fmt.Errorf("no key descriptors in metadata")
	}

	for i, kd := range idpDesc.KeyDescriptors {
		// Only process signing keys
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}

		for _, certData := range kd.KeyInfo.X509Data.X509Certificates {
			// Base64 decode the certificate data
			certBytes, err := base64.StdEncoding.DecodeString(certData.Data)
			if err != nil {
				v.addResult(false, fmt.Sprintf("Certificate %d base64 decode failed", i), "error", err.Error())
				continue
			}

			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				v.addResult(false, fmt.Sprintf("Certificate %d parsing failed", i), "error", err.Error())
				continue
			}

			// Validate certificate expiration
			now := time.Now()
			if now.Before(cert.NotBefore) {
				v.addResult(false, fmt.Sprintf("Certificate %d not yet valid", i), "error",
					fmt.Sprintf("Not before: %s", cert.NotBefore))
				continue
			}
			if now.After(cert.NotAfter) {
				v.addResult(false, fmt.Sprintf("Certificate %d expired", i), "critical",
					fmt.Sprintf("Expired: %s", cert.NotAfter))
				continue
			}

			// Validate RSA key size
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				keySize := rsaKey.N.BitLen()
				if keySize < 2048 {
					v.addResult(false, fmt.Sprintf("Certificate %d has weak key", i), "critical",
						fmt.Sprintf("RSA key size: %d bits (minimum: 2048)", keySize))
					return fmt.Errorf("certificate %d: RSA key size %d < 2048 bits", i, keySize)
				}
				v.addResult(true, fmt.Sprintf("Certificate %d: RSA-%d, valid until %s", i, keySize, cert.NotAfter.Format("2006-01-02")), "info", "")
			} else {
				v.addResult(false, fmt.Sprintf("Certificate %d: non-RSA key", i), "warning", "Only RSA keys are validated")
			}

			v.certificates = append(v.certificates, cert)
		}
	}

	if len(v.certificates) == 0 {
		v.addResult(false, "No valid signing certificates", "error", "")
		return fmt.Errorf("no valid certificates found")
	}

	v.addResult(true, fmt.Sprintf("Found %d valid signing certificate(s)", len(v.certificates)), "info", "")
	return nil
}

func (v *verifier) startACSServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/saml/acs", v.handleACS)

	// Use specified port
	port := v.acsPort

	// Use public ACS URL if provided, otherwise use localhost
	if *acsURL != "" {
		v.acsURL = *acsURL
		printInfo("Using public ACS URL: %s", v.acsURL)
	} else {
		v.acsURL = fmt.Sprintf("http://localhost:%d/saml/acs", port)
	}

	// Set default SP entity ID if not provided
	if v.spEntityID == "" {
		if *acsURL != "" {
			// Derive SP entity ID from public ACS URL (remove /acs suffix)
			baseURL := strings.TrimSuffix(*acsURL, "/acs")
			v.spEntityID = baseURL
		} else {
			v.spEntityID = fmt.Sprintf("http://localhost:%d/saml", port)
		}
	}

	v.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := v.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("ACS server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	printSuccess("ACS server listening on port %d", port)
	printInfo("ACS URL: %s", v.acsURL)
	printInfo("SP Entity ID: %s", v.spEntityID)

	return nil
}

func (v *verifier) stopACSServer() {
	if v.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v.server.Shutdown(ctx)
	}
}

func (v *verifier) handleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	samlResponseB64 := r.FormValue("SAMLResponse")
	if samlResponseB64 == "" {
		http.Error(w, "SAMLResponse parameter missing", http.StatusBadRequest)
		return
	}

	// Decode base64
	samlResponseBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
		return
	}

	// Parse the response to check status before showing success message
	var response saml.Response
	if err := xml.Unmarshal(samlResponseBytes, &response); err != nil {
		http.Error(w, "Failed to parse SAML response", http.StatusBadRequest)
		return
	}

	// Check if the response indicates success or error
	successStatus := "urn:oasis:names:tc:SAML:2.0:status:Success"
	isSuccess := response.Status.StatusCode.Value == successStatus

	// Send response through channel
	select {
	case v.responseChan <- samlResponseBytes:
		// Display appropriate page based on status
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if isSuccess {
			// Success page
			fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>SAML Verification</title>
</head>
<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
	<h1 style="color: green;">✓ Authentication Successful</h1>
	<p>SAML response received. You can close this window.</p>
	<p style="color: #666; margin-top: 30px;">The verifier is now processing your response...</p>
	<p style="margin-top: 20px;">This window will close automatically in <span id="countdown">5</span> seconds.</p>
	<button onclick="window.close()" style="margin-top: 20px; padding: 10px 20px; font-size: 16px; cursor: pointer; background-color: #4CAF50; color: white; border: none; border-radius: 4px;">Close Now</button>
	<script>
		let timeLeft = 5;
		const countdownElement = document.getElementById('countdown');
		const timer = setInterval(() => {
			timeLeft--;
			countdownElement.textContent = timeLeft;
			if (timeLeft <= 0) {
				clearInterval(timer);
				window.close();
			}
		}, 1000);
	</script>
</body>
</html>`)
		} else {
			// Error page
			statusCode := response.Status.StatusCode.Value
			statusMessage := ""
			if response.Status.StatusMessage != nil {
				statusMessage = response.Status.StatusMessage.Value
			}

			// Extract the last part of the status code URN for display
			statusParts := strings.Split(statusCode, ":")
			statusDisplay := statusCode
			if len(statusParts) > 0 {
				statusDisplay = statusParts[len(statusParts)-1]
			}

			fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>SAML Verification - Error</title>
</head>
<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
	<h1 style="color: red;">✗ Authentication Failed</h1>
	<p style="color: #333; font-size: 18px; margin-top: 20px;">The Identity Provider returned an error.</p>
	<div style="background-color: #fee; border: 1px solid #fcc; border-radius: 4px; padding: 20px; margin: 30px auto; max-width: 600px; text-align: left;">
		<p style="margin: 0 0 10px 0;"><strong>Status:</strong> <code style="background-color: #fdd; padding: 2px 6px; border-radius: 3px;">%s</code></p>
		%s
	</div>
	<p style="color: #666; margin-top: 30px;">The verifier will continue processing to show detailed error information...</p>
	<button onclick="window.close()" style="margin-top: 20px; padding: 10px 20px; font-size: 16px; cursor: pointer; background-color: #d32f2f; color: white; border: none; border-radius: 4px;">Close Now</button>
</body>
</html>`, statusDisplay, func() string {
				if statusMessage != "" {
					return fmt.Sprintf(`<p style="margin: 10px 0 0 0;"><strong>Message:</strong> %s</p>`, statusMessage)
				}
				return ""
			}())
		}
	default:
		http.Error(w, "Response already received", http.StatusBadRequest)
	}
}

func (v *verifier) generateAuthnRequest() (string, error) {
	// Generate random request ID
	requestIDBytes := make([]byte, 20)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate request ID: %w", err)
	}
	v.requestID = "id-" + hex.EncodeToString(requestIDBytes)

	// Find SSO URL from metadata
	var ssoURL string
	if len(v.metadata.IDPSSODescriptors) > 0 {
		for _, sso := range v.metadata.IDPSSODescriptors[0].SingleSignOnServices {
			if strings.Contains(sso.Binding, "HTTP-Redirect") {
				ssoURL = sso.Location
				break
			}
		}
	}

	if ssoURL == "" {
		return "", fmt.Errorf("no HTTP-Redirect binding found in metadata")
	}

	// Create AuthnRequest with explicit namespaces
	now := time.Now().UTC()

	// Build AuthnRequest manually - compact format without extra whitespace
	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		v.requestID,
		now.Format("2006-01-02T15:04:05Z"),
		ssoURL,
		v.acsURL,
		v.spEntityID,
	)

	xmlBytes := []byte(xmlStr)

	if *verbose {
		printInfo("AuthnRequest XML:\n%s", string(xmlBytes))
	}

	// Apply HTTP-Redirect binding encoding: deflate -> base64 -> URL encode
	var deflated bytes.Buffer
	flateWriter, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := flateWriter.Write(xmlBytes); err != nil {
		return "", err
	}
	flateWriter.Close()

	encoded := base64.StdEncoding.EncodeToString(deflated.Bytes())

	// Build authorization URL
	authURL, err := url.Parse(ssoURL)
	if err != nil {
		return "", fmt.Errorf("invalid SSO URL: %w", err)
	}

	// Some IdPs are picky about encoding - try building the query string manually
	// to have more control over the encoding
	query := url.Values{}
	query.Set("SAMLRequest", encoded)

	// Use the encoded query string
	authURL.RawQuery = query.Encode()

	if *verbose {
		printInfo("Request ID: %s", v.requestID)
		printInfo("SSO URL: %s", ssoURL)
		printInfo("SP Entity ID: %s", v.spEntityID)
		printInfo("ACS URL: %s", v.acsURL)
		printInfo("Encoded SAMLRequest length: %d bytes", len(encoded))
		printInfo("Deflated size: %d bytes", deflated.Len())

		// Try to decode and inflate to verify encoding
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			printWarning("Failed to verify base64 encoding: %v", err)
		} else {
			inflated := bytes.NewBuffer(nil)
			r := flate.NewReader(bytes.NewReader(decoded))
			if _, err := io.Copy(inflated, r); err != nil {
				printWarning("Failed to verify deflate encoding: %v", err)
			} else {
				printInfo("Verified: Encoding round-trip successful")
				printInfo("Decoded XML:\n%s", inflated.String())
			}
			r.Close()
		}

		printInfo("Full auth URL (length: %d): %s", len(authURL.String()), authURL.String())
	}

	return authURL.String(), nil
}

func (v *verifier) parseSAMLResponse() (*saml.Response, error) {
	if *verbose {
		printInfo("Raw SAML Response XML:\n%s", string(v.samlResponse))
	}

	var response saml.Response
	if err := xml.Unmarshal(v.samlResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SAML response: %w", err)
	}

	if *verbose {
		printInfo("Response ID: %s", response.ID)
		printInfo("InResponseTo: %s", response.InResponseTo)
		if response.Status.StatusCode.Value != "" {
			printInfo("Status: %s", response.Status.StatusCode.Value)
		}
	}

	return &response, nil
}

func (v *verifier) validateResponse(response *saml.Response) error {
	// Check status
	successStatus := "urn:oasis:names:tc:SAML:2.0:status:Success"
	if response.Status.StatusCode.Value != successStatus {
		v.addResult(false, "Response status is not Success", "error",
			fmt.Sprintf("Status: %s", response.Status.StatusCode.Value))
		if response.Status.StatusMessage != nil {
			return fmt.Errorf("IdP returned error: %s", response.Status.StatusMessage.Value)
		}
		return fmt.Errorf("IdP returned status: %s", response.Status.StatusCode.Value)
	}
	v.addResult(true, "Response status: Success", "info", "")

	// Validate InResponseTo
	if response.InResponseTo != v.requestID {
		v.addResult(false, "InResponseTo mismatch", "critical",
			fmt.Sprintf("Expected: %s, Got: %s", v.requestID, response.InResponseTo))
		return fmt.Errorf("InResponseTo does not match request ID")
	}
	v.addResult(true, "InResponseTo matches request ID", "info", "")

	// Validate Destination
	if response.Destination != v.acsURL {
		v.addResult(false, "Destination mismatch", "warning",
			fmt.Sprintf("Expected: %s, Got: %s", v.acsURL, response.Destination))
	}

	// SAML 2.0 spec requires at least one signature (Response OR Assertion)
	// We validate both if present, but require at least one
	// Store signature validation results to check later
	return nil
}

func (v *verifier) validateAssertion(response *saml.Response) error {
	if response.Assertion == nil {
		v.addResult(false, "No assertion in response", "error", "")
		return fmt.Errorf("response contains no assertion")
	}

	assertion := response.Assertion

	// Validate assertion signature using original XML bytes
	// We need to extract the Assertion element from the original response
	// because xml.Marshal would change the formatting and break signature validation
	assertionBytes, err := extractAssertionFromResponse(v.samlResponse)
	if err != nil {
		return fmt.Errorf("failed to extract assertion: %w", err)
	}

	// Check if assertion has a signature
	assertionHasSignature := bytes.Contains(assertionBytes, []byte("<Signature")) ||
		bytes.Contains(assertionBytes, []byte(":Signature"))

	// Check if response has its own signature (after the Assertion element)
	responseHasSignature := bytes.Contains(v.samlResponse, []byte("</saml:Assertion>")) &&
		bytes.Index(v.samlResponse, []byte("Signature")) > bytes.LastIndex(v.samlResponse, []byte("</saml:Assertion>"))

	if *verbose {
		printInfo("Assertion has signature: %v", assertionHasSignature)
		printInfo("Response has signature: %v", responseHasSignature)
	}

	if !assertionHasSignature && !responseHasSignature {
		v.addResult(false, "Neither Response nor Assertion is signed", "critical", "SAML 2.0 requires at least one signature")
		return fmt.Errorf("no signatures found in response or assertion")
	}

	// Validate assertion signature if present
	if assertionHasSignature {
		if err := v.validateSignature(assertionBytes, "Assertion"); err != nil {
			return err
		}
	} else {
		v.addResult(true, "Assertion not signed (Response is signed)", "info", "")
	}

	// Validate response signature if present
	if responseHasSignature {
		if err := v.validateSignature(v.samlResponse, "Response"); err != nil {
			return err
		}
	}

	// Validate time conditions
	now := time.Now()
	if assertion.Conditions != nil {
		if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
			v.addResult(false, "Assertion not yet valid", "error",
				fmt.Sprintf("NotBefore: %s", assertion.Conditions.NotBefore))
			return fmt.Errorf("assertion not yet valid")
		}

		if !assertion.Conditions.NotOnOrAfter.IsZero() && now.After(assertion.Conditions.NotOnOrAfter) {
			v.addResult(false, "Assertion expired", "error",
				fmt.Sprintf("NotOnOrAfter: %s", assertion.Conditions.NotOnOrAfter))
			return fmt.Errorf("assertion expired")
		}

		v.addResult(true, "Assertion time conditions valid", "info",
			fmt.Sprintf("Valid from %s to %s", assertion.Conditions.NotBefore.Format(time.RFC3339),
				assertion.Conditions.NotOnOrAfter.Format(time.RFC3339)))

		// Validate audience restriction
		if len(assertion.Conditions.AudienceRestrictions) > 0 {
			found := false
			for _, ar := range assertion.Conditions.AudienceRestrictions {
				if ar.Audience.Value == v.spEntityID {
					found = true
					break
				}
			}
			if !found {
				v.addResult(false, "Audience restriction failed", "error",
					fmt.Sprintf("SP entity ID '%s' not in audience", v.spEntityID))
				return fmt.Errorf("audience restriction validation failed")
			}
			v.addResult(true, "Audience restriction validated", "info", "")
		}
	}

	// Validate Subject
	if assertion.Subject == nil {
		v.addResult(false, "Subject missing", "error", "")
		return fmt.Errorf("assertion has no subject")
	}

	if assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		v.addResult(false, "NameID missing", "error", "")
		return fmt.Errorf("subject has no NameID")
	}

	v.addResult(true, fmt.Sprintf("NameID: %s", assertion.Subject.NameID.Value), "info", "")

	// Validate AuthnStatement
	if len(assertion.AuthnStatements) == 0 {
		v.addResult(false, "No AuthnStatement", "warning", "Cannot confirm authentication occurred")
	} else {
		v.addResult(true, "AuthnStatement present", "info", "")
	}

	return nil
}

func (v *verifier) validateSignature(xmlData []byte, elementType string) error {
	// Parse XML to extract signature
	var doc interface{}
	if err := xml.Unmarshal(xmlData, &doc); err != nil {
		return fmt.Errorf("failed to parse XML for signature validation: %w", err)
	}

	// Check for signature element (with or without namespace prefix)
	hasSignature := bytes.Contains(xmlData, []byte("<Signature")) ||
		bytes.Contains(xmlData, []byte(":Signature"))

	if !hasSignature {
		v.addResult(false, fmt.Sprintf("%s not signed", elementType), "error", "Signature required")
		return fmt.Errorf("%s is not signed", elementType)
	}

	// Extract signature method algorithm
	algorithm := extractSignatureMethod(xmlData)
	if algorithm != "" {
		if *verbose {
			printInfo("Signature algorithm: %s", algorithm)
		}

		// Check for deprecated SHA-1
		if strings.Contains(strings.ToLower(algorithm), "sha1") {
			if *skipSHA1 {
				v.addResult(false, fmt.Sprintf("%s signed with SHA-1", elementType), "critical",
					"SHA-1 is cryptographically broken (allowed with -allow-sha1)")
			} else {
				v.addResult(false, fmt.Sprintf("%s signed with SHA-1", elementType), "critical",
					"SHA-1 is cryptographically broken and MUST NOT be used")
				return fmt.Errorf("signature uses deprecated SHA-1 algorithm")
			}
		} else if strings.Contains(strings.ToLower(algorithm), "sha256") || strings.Contains(strings.ToLower(algorithm), "sha512") {
			v.addResult(true, fmt.Sprintf("%s signature algorithm: %s", elementType, algorithm), "info", "")
		}
	}

	// Validate signature using certificates from metadata
	validationErr := fmt.Errorf("signature validation failed with all certificates")
	for i, cert := range v.certificates {
		if err := v.verifySignatureWithCert(xmlData, cert); err == nil {
			v.addResult(true, fmt.Sprintf("%s signature valid (cert %d)", elementType, i), "info", "")
			return nil
		} else {
			validationErr = err
		}
	}

	v.addResult(false, fmt.Sprintf("%s signature invalid", elementType), "critical", validationErr.Error())
	return validationErr
}

func (v *verifier) verifySignatureWithCert(xmlData []byte, cert *x509.Certificate) error {
	// Use goxmldsig for signature validation
	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	// Parse XML into etree.Element
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}

	// Validate signature
	_, err := validationContext.Validate(doc.Root())
	return err
}

func extractAssertionFromResponse(responseXML []byte) ([]byte, error) {
	// Parse the response XML to extract the Assertion element
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return nil, fmt.Errorf("failed to parse response XML: %w", err)
	}

	// Find the Assertion element
	assertion := doc.FindElement("//Assertion")
	if assertion == nil {
		return nil, fmt.Errorf("no Assertion element found in response")
	}

	// Create a new document with just the assertion
	assertionDoc := etree.NewDocument()
	assertionDoc.SetRoot(assertion.Copy())

	// Return the XML bytes
	return assertionDoc.WriteToBytes()
}

func extractSignatureMethod(xmlData []byte) string {
	// Simple XML parsing to extract SignatureMethod Algorithm attribute
	startTag := []byte("<SignatureMethod Algorithm=\"")
	startIdx := bytes.Index(xmlData, startTag)
	if startIdx == -1 {
		return ""
	}

	startIdx += len(startTag)
	endIdx := bytes.Index(xmlData[startIdx:], []byte("\""))
	if endIdx == -1 {
		return ""
	}

	return string(xmlData[startIdx : startIdx+endIdx])
}

func (v *verifier) extractAttributes(response *saml.Response) error {
	if response.Assertion == nil {
		return fmt.Errorf("no assertion to extract attributes from")
	}

	assertion := response.Assertion

	if len(assertion.AttributeStatements) == 0 {
		v.addResult(false, "No AttributeStatement", "warning", "No user attributes provided")
		return nil
	}

	// Extract attributes into map
	attributes := make(map[string][]string)
	for _, attrStatement := range assertion.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			var values []string
			for _, val := range attr.Values {
				values = append(values, val.Value)
			}
			attributes[attr.Name] = values
		}
	}

	if len(attributes) == 0 {
		v.addResult(false, "No attributes in AttributeStatement", "warning", "")
		return nil
	}

	// Check for required SAML attributes
	requiredAttrs := []string{"email"}
	missingAttrs := []string{}

	for _, attrName := range requiredAttrs {
		values, ok := attributes[attrName]
		if !ok || len(values) == 0 {
			missingAttrs = append(missingAttrs, attrName)
		} else {
			v.addResult(true, fmt.Sprintf("Attribute '%s': %s", attrName, strings.Join(values, ", ")), "info", "")
		}
	}

	if len(missingAttrs) > 0 {
		v.addResult(false, "Missing required attributes", "warning",
			fmt.Sprintf("Missing: %s", strings.Join(missingAttrs, ", ")))
	}

	// Display all attributes in verbose mode
	if *verbose {
		fmt.Println()
		printInfo("All attributes:")
		for name, values := range attributes {
			fmt.Printf("  %s = %s\n", name, strings.Join(values, ", "))
		}
	}

	return nil
}

func (v *verifier) addResult(passed bool, message, level, detail string) {
	v.results = append(v.results, verificationResult{
		passed:  passed,
		message: message,
		level:   level,
		detail:  detail,
	})
}

func (v *verifier) displayResults() {
	fmt.Println()
	printHeader("Verification Results")
	fmt.Println()

	passCount := 0
	warnCount := 0
	errorCount := 0
	criticalCount := 0

	for _, result := range v.results {
		icon := "✓"
		color := colorGreen

		if !result.passed {
			icon = "✗"
			switch result.level {
			case "warning":
				color = colorYellow
				warnCount++
			case "error":
				color = colorRed
				errorCount++
			case "critical":
				color = colorRed
				criticalCount++
			}
		} else {
			passCount++
		}

		fmt.Printf("%s%s %s%s\n", color, icon, result.message, colorReset)
		if result.detail != "" {
			fmt.Printf("  %s%s%s\n", colorCyan, result.detail, colorReset)
		}
	}

	fmt.Println()
	printHeader("Summary")
	fmt.Printf("%sPassed: %d%s\n", colorGreen, passCount, colorReset)
	if warnCount > 0 {
		fmt.Printf("%sWarnings: %d%s\n", colorYellow, warnCount, colorReset)
	}
	if errorCount > 0 {
		fmt.Printf("%sErrors: %d%s\n", colorRed, errorCount, colorReset)
	}
	if criticalCount > 0 {
		fmt.Printf("%sCritical: %d%s\n", colorRed, criticalCount, colorReset)
	}

	fmt.Println()
	if criticalCount > 0 || errorCount > 0 {
		printError("Verification FAILED - Critical security issues found")
		os.Exit(1)
	} else if warnCount > 0 {
		printWarning("Verification completed with warnings")
	} else {
		printSuccess("Verification PASSED - All checks successful!")
	}
}

// Utility functions for colored output
func printHeader(msg string) {
	fmt.Printf("%s=== %s ===%s\n", colorBlue, msg, colorReset)
}

func printStep(msg string) {
	fmt.Printf("\n%s▶ %s%s\n", colorCyan, msg, colorReset)
}

func printInfo(format string, args ...interface{}) {
	fmt.Printf("%sℹ %s%s\n", colorBlue, fmt.Sprintf(format, args...), colorReset)
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf("%s✓ %s%s\n", colorGreen, fmt.Sprintf(format, args...), colorReset)
}

func printWarning(format string, args ...interface{}) {
	fmt.Printf("%s⚠ %s%s\n", colorYellow, fmt.Sprintf(format, args...), colorReset)
}

func printError(format string, args ...interface{}) {
	fmt.Printf("%s✗ %s%s\n", colorRed, fmt.Sprintf(format, args...), colorReset)
}
