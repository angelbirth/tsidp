# SAML 2.0 Identity Provider Verifier

The SAML verifier validates that a SAML 2.0 Identity Provider implementation is correct and complete. It performs automated testing of the SAML SSO flow, metadata validation, assertion verification, and signature checking.

## Features

The verifier tests the following:

1. **SAML Metadata** - Validates IdP metadata structure, endpoints, and certificates
2. **SSO Flow** - Tests complete SP-initiated authentication flow
3. **Signature Validation** - Verifies XML signatures with security checks
4. **Assertion Validation** - Validates time conditions, audience, and subject
5. **Attribute Extraction** - Extracts and validates standard SAML attributes (email)
6. **Security Checks** - Enforces RSA-SHA256+, rejects SHA-1, validates key sizes ≥2048 bits
7. **Binding Support** - Tests HTTP-Redirect (AuthnRequest) and HTTP-POST (Response) bindings

## Usage

### Test using mocksaml.com:

```bash
$ go run . -v -idp-metadata-url https://mocksaml.com/api/saml/metadata
```

### Test against tsidp (to be implemented)

Note: metadata automatically fetched from `{idp-host}/saml/metadata`

```bash
$ go run . -v -idp http://tsidp-hostname.my-tn.ts.net

or

$ go run . -v -idp-metadata-url http://tsidp-hostname.my-tn.ts.net/saml/metadata
```

### Options

- `-idp` - IdP base URL (required unless `-idp-metadata-url` is provided)
- `-idp-metadata-url` - Direct URL to IdP metadata XML (overrides `-idp`)
- `-acs-port` - Port for ACS server to listen on (default: 58080)
- `-acs-url` - Public-facing ACS URL (for funnel URI, usually not needed)
- `-sp-entity-id` - Service Provider entity ID (default: auto-generated)
- `-allow-sha1` - Allow SHA-1 signatures (not recommended, for testing only)
- `-v` - Verbose output

## How It Works

1. **Fetches IdP metadata** from common endpoints (`/saml/metadata`)
2. **Validates metadata structure** including certificates, endpoints, and bindings
3. **Starts local ACS server** to receive SAML responses
4. **Generates AuthnRequest** with HTTP-Redirect binding (deflate + base64 + URL encoding)
5. **Displays authorization URL** for manual browser authentication
6. **Captures SAML response** automatically via HTTP-POST
7. **Validates signatures** using certificates from metadata with algorithm checks
8. **Validates assertions** including time conditions, audience restrictions, and subject
9. **Extracts attributes** and validates required fields (uid, email, displayName)
10. **Displays comprehensive results** with pass/fail status and security warnings

## Security Validation

The verifier enforces modern security standards:

- **Signature Algorithms**: Requires RSA-SHA256 or RSA-SHA512, rejects deprecated SHA-1
- **Key Sizes**: Enforces minimum 2048-bit RSA keys
- **Certificate Validation**: Checks expiration dates and key strength
- **Time Validation**: Validates NotBefore/NotOnOrAfter conditions
- **Audience Validation**: Ensures SP entity ID matches assertion audience
- **InResponseTo Validation**: Verifies response matches original request

## Output

The verifier produces color-coded output:

- ✓ (green) - Test passed
- ✗ (red) - Test failed (error or critical)
- ⚠ (yellow) - Warning

Example output:

```
=== SAML 2.0 Identity Provider Verifier ===
ℹ Testing IdP: http://localhost:8080

▶ Step 1: Fetching IdP metadata
✓ Found metadata at: http://localhost:8080/saml/metadata
✓ Metadata fetched successfully

▶ Step 2: Validating metadata
✓ EntityID: http://localhost:8080/saml
✓ IDPSSODescriptor found
✓ HTTP-Redirect binding supported
✓ HTTP-POST binding supported
✓ Certificate 0: RSA-2048, valid until 2025-12-31
✓ Found 1 valid signing certificate(s)

▶ Step 3: Starting local ACS server
✓ ACS server listening on port 8080
ℹ ACS URL: http://localhost:8080/saml/acs
ℹ SP Entity ID: http://localhost:8080/saml

▶ Step 4: Generating AuthnRequest
✓ AuthnRequest generated

▶ Step 5: Waiting for user authentication

ℹ Please open this URL in your browser to authenticate:
http://localhost:8080/saml/sso?SAMLRequest=...

ℹ Waiting for SAML response (press Ctrl+C to cancel)...
✓ SAML response received!

▶ Step 6: Parsing SAML response

▶ Step 7: Validating SAML response and signatures
✓ Response status: Success
✓ InResponseTo matches request ID
✓ Response signature algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
✓ Response signature valid (cert 0)

▶ Step 8: Validating assertion
✓ Assertion signature algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
✓ Assertion signature valid (cert 0)
✓ Assertion time conditions valid
✓ Audience restriction validated
✓ NameID: alice@example.com
✓ AuthnStatement present

▶ Step 9: Extracting user attributes
✓ Attribute 'email': alice@example.com

=== Verification Results ===

✓ Passed: 20

=== Summary ===
Passed: 20

✓ Verification PASSED - All checks successful!
```

## See Also

- [plan.md](plan.md) - Detailed implementation plan
- SAML 2.0 Core Specification: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- SAML 2.0 Bindings: http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
