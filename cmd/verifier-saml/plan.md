# SAML Verifier Implementation Plan

## Overview

This verifier validates that tsidp's SAML 2.0 Identity Provider implementation is correct and complete. It performs automated testing of the SAML SSO flow, metadata validation, assertion verification, and signature checking.

The verifier tests six critical areas: (1) SAML metadata endpoint validation ensuring proper IdP configuration and certificate distribution, (2) complete SP-initiated SSO flow with proper HTTP-Redirect and HTTP-POST binding support, (3) comprehensive response and assertion validation including signature verification and security checks, (4) standard SAML attribute extraction and validation (uid, email, displayName), (5) SAML binding support (HTTP-Redirect for requests, HTTP-POST for responses), and (6) cryptographic security enforcement including RSA-SHA256+ signature algorithms, minimum 2048-bit key sizes, and rejection of deprecated SHA-1.

The execution flow automates the complete SAML authentication cycle: parse command-line flags to configure the test (including IdP URL, ACS port, and optional SP entity ID), fetch and validate IdP metadata with certificate extraction, start a local callback server to receive responses, generate a properly encoded AuthnRequest and display the authorization URL for user authentication, automatically capture the SAML response via HTTP-POST, perform comprehensive validation of signatures (with algorithm and key size checks), assertions (time conditions, audience, InResponseTo matching), and standard SAML attributes (uid, email, displayName), then display a detailed summary with pass/fail status, security warnings, and actionable recommendations.

## Core Requirements - What Must Be Verified

### 1. SAML Metadata Endpoint ✅ CRITICAL

**Why**: Metadata is the foundation of SAML - it describes IdP capabilities, endpoints, and certificates

**What to verify**:

- Endpoint accessible at `/saml/metadata` or `/.well-known/saml-metadata.xml`
- Valid XML structure conforming to SAML 2.0 metadata schema
- Contains EntityDescriptor with unique entityID
- IDPSSODescriptor is present with valid signing certificates
- SingleSignOnService endpoints are defined (HTTP-Redirect and/or HTTP-POST bindings)
- X.509 certificate is present and valid for signature verification

**Implementation Notes**:

- Use `github.com/crewjam/saml` to parse and validate metadata
- Extract and store **all** signing certificates for key rollover support
- Store certificates indexed by KeyInfo/KeyName for signature verification lookup
- Verify certificates are not expired
- **SECURITY**: Enforce minimum RSA key size of 2048 bits (fail if smaller)

---

### 2. SAML SSO Flow (SP-Initiated) ✅ CRITICAL

**Why**: This is the primary authentication flow - users must be able to log in via SAML

**What to verify**:

- Generate valid AuthnRequest (SP → IdP)
- AuthnRequest includes required attributes: ID, IssueInstant, Destination, AssertionConsumerServiceURL
- Proper URL encoding and deflate compression for HTTP-Redirect binding
- IdP accepts and processes the AuthnRequest
- Response contains valid SAML assertion
- Assertion includes AuthnStatement confirming authentication occurred

**Implementation Notes**:

- Use `github.com/crewjam/saml` to generate AuthnRequest
- Generate random AuthnRequest ID for later validation (InResponseTo matching)
- Apply deflate compression and Base64 encoding for HTTP-Redirect binding
- Store AuthnRequest ID for InResponseTo validation
- Display authorization URL for user to authenticate in browser

---

### 3. SAML Response & Assertion Validation ✅ CRITICAL

**Why**: The core security mechanism - ensures assertions are authentic and trustworthy

**What to verify**:

- Response signature verification using IdP's public certificate from metadata
- Assertion signature verification (if separately signed)
- Response/Assertion not expired (NotBefore/NotOnOrAfter conditions)
- Response InResponseTo matches original AuthnRequest ID
- Assertion Subject confirmation (recipient validation)
- Assertion audience restriction matches SP entityID
- NameID is present
- **SECURITY**: Signature algorithm validation (RSA-SHA256+ required, RSA-SHA1 rejected)
- **SECURITY**: Certificate selection based on KeyInfo in signature (key rollover support)

**Implementation Notes**:

- Use `github.com/crewjam/saml` for XML signature verification (via embedded `goxmldsig`)
- Implement custom validation logic on top of library:
  - Don't blindly trust library defaults
  - Explicitly verify each security-critical field
  - Apply our own security policies (algorithm checks, key size, etc.)
- Check time-based conditions against current time
- Validate all security-critical fields
- Provide clear error messages for each validation failure
- **SECURITY**: Extract signature algorithm from SignatureMethod element
- **SECURITY**: REJECT signatures using SHA-1 (return CRITICAL error)
- **SECURITY**: Match certificate from signature KeyInfo to metadata certificates
- **SECURITY**: Support multiple certificates for key rollover scenarios
- If KeyInfo contains X509Data, validate it matches a known metadata certificate
- If no KeyInfo present, try all metadata certificates until one succeeds

---

### 4. Attribute Statements ✅ IMPORTANT

**Why**: Applications need user information from the IdP

**What to verify** (Standard SAML attributes):

- `email` - User email address (required)

**Implementation Notes**:

- Parse AttributeStatement from assertion
- Verify presence of required attributes: email
- Display all attributes in final output
- Validate attribute value formats match expected types

---

### 5. Multiple Binding Support ✅ IMPORTANT

**What are SAML Bindings?**

SAML bindings define **how** SAML protocol messages are transported between parties (SP ↔ IdP). They specify the encoding, compression, and HTTP method used to send SAML XML messages.

**Why**: These specific bindings are the industry standard for production SAML implementations

**What to verify**:

1. **HTTP-Redirect Binding (for AuthnRequest - SP → IdP)**

   - **Why this matters**: Most common way for SPs to initiate SSO
   - **How it works**:
     - AuthnRequest XML is compressed (DEFLATE), Base64-encoded, URL-encoded
     - Sent as GET parameter: `?SAMLRequest=<encoded-data>`
     - User's browser redirects to IdP with encoded request in URL
   - **Limitations**: URL length limits (~2KB) - only suitable for small messages like AuthnRequest
   - **Security**: Visible in browser history and server logs (doesn't contain secrets)

2. **HTTP-POST Binding (for SAML Response - IdP → SP)**
   - **Why this matters**: Industry standard for responses containing assertions
   - **How it works**:
     - SAML Response XML is Base64-encoded (no compression)
     - Sent via HTTP POST as form parameter: `SAMLResponse=<encoded-data>`
     - IdP returns HTML form with auto-submit JavaScript to user's browser
   - **Why POST not Redirect**: Responses with assertions are too large for URL parameters (often >4KB)
   - **Security**: Not visible in browser history, more appropriate for sensitive assertion data

**Implementation Notes**:

- **HTTP-Redirect (AuthnRequest)**:
  - Implement: DEFLATE compression → Base64 encoding → URL encoding
  - Generate proper query string: `?SAMLRequest=...&RelayState=...`
- **HTTP-POST (Response)**:
  - Implement: Base64 decoding only (no decompression)
  - Parse form-encoded POST body to extract `SAMLResponse` parameter
- Verify IdP metadata lists both bindings in `SingleSignOnService` elements

---

### 6. XML Signature Algorithms ✅ CRITICAL

**Why**: Weak cryptography undermines all security guarantees

**What to verify**:

- **REQUIRED**: RSA-SHA256 or RSA-SHA512 (modern, secure)
- **REJECTED**: RSA-SHA1 (deprecated, cryptographically broken)
- Proper handling of signature canonicalization (C14N)
- Minimum key size enforcement (2048+ bits for RSA)

**Implementation Notes**:

- Extract SignatureMethod from XML signature element
- **CRITICAL ERROR** if algorithm is RSA-SHA1 or other deprecated algorithms
- Report which signature algorithm was used
- Verify key size from certificate: extract RSA public key, check bit length ≥2048
- Fail verification if key size < 2048 bits
- Test signature verification with different canonicalization methods (C14N, C14N11, Exclusive C14N)
- Reference: NIST deprecated SHA-1 for digital signatures (FIPS 180-4)

---

### 7. Error Handling ✅ CRITICAL

**Why**: Ensures graceful degradation and helpful debugging - critical for production readiness

**What to verify**:

- Invalid signature handling
- Expired assertion handling
- Missing required fields
- Error status codes in SAML responses
- Clear, actionable error messages for each failure type

**Implementation Notes**:

- Handle and report errors clearly at each validation step
- Distinguish between IdP errors (status codes in response) and validation errors
- Provide specific guidance on how to fix common issues
- Test robustness against malformed responses

---

## Optional But Recommended Verifications

## Implementation Structure

```
cmd/verifier-saml/
├── verifier-saml.go          # Main verification logic and flow
├── validation.go             # Custom security validation on top of crewjam/saml
│                             # - Signature algorithm checking (reject SHA-1)
│                             # - RSA key size validation (≥2048 bits)
│                             # - Certificate expiration checks
│                             # - Custom error messages for each validation
└── plan.md                   # This file
```

### Execution Flow

1. **Step 1: Parse command-line flags** (similar to OIDC verifier)

   - `-idp` URL (required)
   - `-acs-port` Local ACS server port (default: random high port)
   - `-sp-entity-id` Service Provider entity ID (optional, auto-generated if not provided)
     - Default: `http://localhost:<acs-port>/saml`
     - User can override if IdP requires specific entity ID
   - Optional flags for additional tests

2. **Step 2: Fetch and parse SAML metadata** (Core Requirement #1)

   - GET IdP metadata endpoint (`/saml/metadata` or `/.well-known/saml-metadata.xml`)
   - Parse XML structure and validate SAML 2.0 metadata schema
   - Extract EntityDescriptor, IDPSSODescriptor, and SingleSignOnService endpoints
   - Verify HTTP-Redirect and HTTP-POST bindings are present (Requirement #5)
   - Extract **all** signing certificates from IDPSSODescriptor
   - **SECURITY**: Validate each certificate (Requirement #6):
     - Check expiration dates
     - Extract RSA public key and verify ≥2048 bits
     - Store certificate with KeyInfo identifier for lookup
   - Display IdP configuration and certificate details

3. **Step 3: Start local ACS server** (Core Requirement #2, #5)

   - Start temporary HTTP server on localhost (random high port or 8080)
   - Create endpoint to receive SAML response (HTTP-POST binding - Requirement #5)
   - Use this URL as AssertionConsumerServiceURL in AuthnRequest
   - Server captures SAMLResponse parameter automatically

4. **Step 4: Generate AuthnRequest** (Core Requirement #2, #5)

   - Create unique request ID (for InResponseTo validation)
   - Build AuthnRequest XML with: ID, IssueInstant, Destination, AssertionConsumerServiceURL
   - Apply HTTP-Redirect binding encoding (Requirement #5): deflate + base64 + URL encode
   - Generate authorization URL with SAMLRequest parameter
   - Store AuthnRequest ID for later validation

5. **Step 5: Handle user authentication** (Core Requirement #2)

   - Display authorization URL to user
   - User opens URL in browser and authenticates via IdP
   - IdP processes AuthnRequest and authenticates user
   - IdP sends SAML response via HTTP-POST to local ACS server (Requirement #5)
   - Server captures response automatically (no manual paste needed)

6. **Step 6: Extract and decode SAML Response** (Core Requirement #2, #5)

   - Parse SAMLResponse parameter from POST request body (HTTP-POST binding)
   - Base64 decode the response (no decompression for POST binding)
   - Parse XML structure
   - Verify response contains assertion and AuthnStatement
   - Shutdown local ACS server

7. **Step 7: Verify Response signature** (Core Requirement #3, #6)

   - Extract Signature element from Response
   - **SECURITY**: Extract and validate SignatureMethod algorithm (Requirement #6)
     - **CRITICAL ERROR** if RSA-SHA1 or other deprecated algorithm
     - Require RSA-SHA256 or RSA-SHA512
   - Match certificate using KeyInfo (see certificate selection logic in Requirement #3)
   - Verify signature using matched certificate
   - Report signature validation result and algorithm used

8. **Step 8: Validate Assertion** (Core Requirement #3)

   - Extract assertion from response
   - Verify assertion signature (if separately signed)
     - **SECURITY**: Same algorithm and key size checks as Response (Requirement #6)
     - Match certificate using KeyInfo
   - Validate time conditions (NotBefore/NotOnOrAfter)
   - Validate InResponseTo matches request ID
   - Validate Subject confirmation
   - Validate Audience restriction
   - Verify NameID is present and non-empty

9. **Step 9: Extract and validate attributes** (Core Requirement #4)

   - Parse AttributeStatement
   - Verify presence of **required** attributes: uid, email, displayName
   - Display all attributes found in the assertion
   - Highlight missing expected attributes
   - Report validation errors if required attributes are missing

10. **Step 10: Display final summary**
    - All validation results with pass/fail status
    - Security warnings (weak algorithms, expired certs, missing required fields)
    - Binding verification summary (HTTP-Redirect for request ✅, HTTP-POST for response ✅)
    - Recommendations for fixes

---

## Key Differences from OIDC Verifier

| Aspect                  | OIDC                               | SAML                                |
| ----------------------- | ---------------------------------- | ----------------------------------- |
| **Data Format**         | JSON                               | XML                                 |
| **Signature**           | JWT (JWS)                          | XML Digital Signature               |
| **Discovery**           | `.well-known/openid-configuration` | `/saml/metadata`                    |
| **Client Registration** | Dynamic (via API)                  | Static (metadata exchange)          |
| **Request Encoding**    | URL parameters (simple)            | Deflate + Base64 + URL encode       |
| **Token Format**        | JWT (base64)                       | XML (base64)                        |
| **Complexity**          | Lower                              | Higher (XML namespaces, signatures) |

---

## External Dependencies

```go
import (
    "compress/flate"           // For HTTP-Redirect deflate compression
    "encoding/base64"          // For encoding/decoding
    "encoding/xml"             // For XML parsing
    "crypto/x509"              // For certificate handling

    // SAML-specific library
    "github.com/crewjam/saml"  // SAML 2.0 implementation (includes goxmldsig for signatures)
)
```

**Implementation approach**: Use `github.com/crewjam/saml` for core SAML functionality (metadata parsing, AuthnRequest generation, response handling, XML signatures via embedded `goxmldsig`), while implementing custom validation logic on top to enforce security policies (SHA-1 rejection, key size checks, detailed error messages).

---

## Testing Strategy

The verifier is tested against **tsidp** (the primary target):

```bash
# Basic test against tsidp running locally
go run ./cmd/verifier-saml/verifier-saml.go -idp http://localhost:8080

# Test with custom SP entity ID
go run ./cmd/verifier-saml/verifier-saml.go -idp http://localhost:8080 -sp-entity-id https://myapp.example.com/saml

# Test with specific ACS port
go run ./cmd/verifier-saml/verifier-saml.go -idp http://localhost:8080 -acs-port 9090
```

The verifier validates that tsidp correctly implements SAML 2.0 IdP functionality including metadata distribution, SSO flows, signature algorithms, and standard SAML attributes.

---

## Success Criteria

The verifier is complete when:

- ✅ All critical verifications pass against tsidp
- ✅ Clear, actionable error messages for failures
- ✅ Comprehensive output showing all validated fields
- ✅ Similar user experience to OIDC verifier
- ✅ Documentation of how to use the verifier
- ✅ Can identify common SAML implementation issues

---

## Future Enhancements

- Assertion encryption support (SP key pair generation, EncryptedAssertion decryption)
- Automated SP metadata generation
- Interactive mode for testing different configurations
- Detailed protocol trace logging (like `--debug` flag)
- Performance benchmarking
- Concurrent request testing
- SAML artifact binding support
