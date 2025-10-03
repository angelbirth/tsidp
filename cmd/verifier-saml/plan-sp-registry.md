# SAML SP Registry with Admin UI - Implementation Plan

## High Level Overview

This enhancement adds a Service Provider (SP) registry to tsidp, allowing administrators to explicitly register and manage SAML SPs that can authenticate against the IdP. Currently, tsidp accepts any SP Entity ID without validation - this is acceptable for development but production environments need SP registration and verification.

The registry provides:

- **Security**: Whitelist of authorized SPs prevents unauthorized authentication attempts
- **Auditability**: Clear record of which SPs are configured and their allowed ACS URLs
- **Configuration**: Per-SP settings (future: custom attributes, policies)

This follows the same architectural pattern as OAuth client management (see `server/ui.go` and `FunnelClient` storage).

## Architecture & Design

### Code Organization

**server/saml.go** - SP registry data structures and storage

- `SAMLServiceProvider` struct definition
- `storeSAMLServiceProvidersLocked()` - Persist registry to disk
- `loadSAMLServiceProviders()` - Load registry on startup
- SP lookup and validation helpers
- Include tests in saml_test.go
- Modify `serveSAMLSSO()` to validate SP Entity ID and ACS URL
- Return appropriate SAML error responses for unauthorized SPs
- Use slog.Warn to log all SP verification failures

**server/ui_saml.go** - Admin UI handlers for SAML SP management

- `handleSAMLSPList()` - Display registered SPs
- `handleNewSAMLSP()` - Create new SP registration
- `handleEditSAMLSP()` - Edit/delete existing SP
- Follow existing UI patterns from `ui.go`

**server/ui-saml-list.html** - Template for SP list view

- Embedded HTML template (similar to `ui-list.html`)
- Shows Entity ID, Name, and ACS URLs for each SP

**server/ui-saml-edit.html** - Template for SP create/edit form

- Embedded HTML template (similar to `ui-edit.html`)
- Form fields: Name, Entity ID, ACS URLs (textarea, one per line)

**server/server.go** - IDPServer struct updates

- Add `samlServiceProviders map[string]*SAMLServiceProvider` field
- Add `disableSAMLSPVerification bool` field
- Load registry in existing `loadState()` function

**tsidp-server.go** - main entry point

- Add a new flag: `-experimental-disable-saml-sp-verification`, note: only for development
- Pass flag value to IDPServer configuration

### Data Model

```go
// SAMLServiceProvider represents a registered Service Provider
type SAMLServiceProvider struct {
    EntityID string   // Unique identifier (e.g., "https://app.example.com/saml")
    Name     string   // Human-readable display name
    ACSURLs  []string // Allowed Assertion Consumer Service URLs
}
```

**Storage**: `{stateDir}/saml-service-providers.json`

Example JSON structure:

- The data is serialized as an array of objects
- In the go source it is a map keyed by the EntityID

```json
[
  {
    "EntityID": "https://app.example.com/saml",
    "Name": "Example App #1",
    "ACSURLs": ["https://app.example.com/saml/acs", "https://app.example.com/saml/acs/callback"]
  },
  {
    "EntityID": "https://app.example2.com/saml",
    "Name": "Example App #2",
    "ACSURLs": ["https://app.example2.com/saml/acs", "https://app.example2.com/saml/acs/callback"]
  }
]
```

### Integration with Existing tsidp

**UI Integration**:

1. Add "SAML SPs" navigation link to admin UI header template (always visible)
2. Mount handlers on existing UI routes:
   - `/saml/sp` - List SPs (always accessible; shows disabled message if `enableSAML` is false)
   - `/saml/sp/new` - Create new SP (returns 404 if `enableSAML` is false)
   - `/saml/sp/edit/{entityID}` - Edit/delete SP (returns 404 if `enableSAML` is false)
3. Reuse existing UI authentication/authorization checks (`allowAdminUI` capability)
4. Share CSS styling from `ui-style.css`
5. Pass `EnableSAML` boolean to all templates that use the header template to control navigation display

**SSO Flow Integration**:

1. Check if `s.disableSAMLSPVerification` is enabled - if true, skip verification (development only). Log a warning that it is disabled.
2. Extract Entity ID from `AuthnRequest.Issuer.Value`
3. Lookup in `s.samlServiceProviders` map (O(1) operation)
4. If not found: return SAML error (Responder/RequestDenied)
5. Extract ACS URL from `AuthnRequest.AssertionConsumerServiceURL`
6. Validate ACS URL exists in `sp.ACSURLs` slice
7. If mismatch: return SAML error (Responder/RequestDenied)
8. Proceed with normal SSO flow

## Core Requirements

### 1. SAMLServiceProvider Data Structure ✅ CRITICAL

**Purpose**: Minimal data structure to store registered SP information.

**Implementation**:

```go
// In server/saml.go
type SAMLServiceProvider struct {
    EntityID string   `json:"entity_id"` // Unique SP identifier
    Name     string   `json:"name"`      // Display name for admin UI
    ACSURLs  []string `json:"acs_urls"`  // Allowed ACS URLs
}
```

**Key Details**:

- Entity ID serves as both unique identifier and map key
- No metadata XML, certificates, or parsed structures stored
- Simple structure keeps JSON serialization straightforward
- Future enhancements can add fields without breaking changes

### 2. Storage and Persistence ✅ CRITICAL

**Purpose**: Save and load SP registry to/from disk.

**Implementation**:

```go
// In server/saml.go

// storeSAMLServiceProvidersLocked persists the SP registry to disk
// Must be called with s.mu held
func (s *IDPServer) storeSAMLServiceProvidersLocked() error {
    if s.stateDir == "" {
        return nil // No persistence in ephemeral mode
    }

    path := filepath.Join(s.stateDir, "saml-service-providers.json")

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

    path := filepath.Join(stateDir, "saml-service-providers.json")
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
```

**Integration**:

```go
// In server/server.go - Update loadState() function
func (s *IDPServer) loadState() error {
    // ... existing OAuth client loading ...

    // Load SAML SPs
    if s.enableSAML {
        sps, err := loadSAMLServiceProviders(s.stateDir)
        if err != nil {
            return err
        }
        s.samlServiceProviders = sps
        slog.Info("loaded SAML service providers", "count", len(sps))
    }

    return nil
}
```

### 3. Admin UI - List View ✅ CRITICAL

**Purpose**: Display all registered SPs with their Entity IDs and ACS URLs.

**Implementation**:

```go
// In server/ui_saml.go

func (s *IDPServer) handleSAMLSPList(w http.ResponseWriter, r *http.Request) {
    // Check if SAML is enabled
    if !s.enableSAML {
        var buf bytes.Buffer
        if err := samlSPListTmpl.Execute(&buf, samlSPListData{SAMLDisabled: true}); err != nil {
            writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
                "failed to render SP list", err)
            return
        }
        buf.WriteTo(w)
        return
    }

    s.mu.Lock()
    sps := make([]samlSPDisplayData, 0, len(s.samlServiceProviders))
    for _, sp := range s.samlServiceProviders {
        sps = append(sps, samlSPDisplayData{
            EntityID: sp.EntityID,
            Name:     sp.Name,
            ACSURLs:  sp.ACSURLs,
        })
    }
    s.mu.Unlock()

    // Sort by name, then Entity ID
    sort.Slice(sps, func(i, j int) bool {
        if sps[i].Name != sps[j].Name {
            return sps[i].Name < sps[j].Name
        }
        return sps[i].EntityID < sps[j].EntityID
    })

    var buf bytes.Buffer
    if err := samlSPListTmpl.Execute(&buf, samlSPListData{ServiceProviders: sps}); err != nil {
        writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
            "failed to render SP list", err)
        return
    }
    buf.WriteTo(w)
}

type samlSPDisplayData struct {
    EntityID string
    Name     string
    ACSURLs  []string
    Success  string
    Error    string
    IsNew    bool
    IsEdit   bool
}

type samlSPListData struct {
    ServiceProviders []samlSPDisplayData
    SAMLDisabled     bool
}
```

**Template** (`server/ui-saml-list.html`):

```html
{{template "header" .}}

<h1>SAML Service Providers</h1>

{{if .SAMLDisabled}}
<div class="info">
    <p>SAML is currently disabled on this IdP server.</p>
    <p>To enable SAML, restart the server with the <code>-experimental-enable-saml</code> flag.</p>
</div>
{{else}}
<p><a href="/saml/sp/new" class="button">Register New SP</a></p>

{{if .ServiceProviders}}
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Entity ID</th>
            <th>ACS URLs</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {{range .ServiceProviders}}
        <tr>
            <td>{{.Name}}</td>
            <td><code>{{.EntityID}}</code></td>
            <td>
                {{range .ACSURLs}}
                <div><code>{{.}}</code></div>
                {{end}}
            </td>
            <td>
                <a href="/saml/sp/edit/{{.EntityID | urlquery}}">Edit</a>
            </td>
        </tr>
        {{end}}
    </tbody>
</table>
{{else}}
<p>No SAML service providers registered yet.</p>
<p><a href="/saml/sp/new">Register your first SP</a></p>
{{end}}
{{end}}

</body>
</html>
```

### 4. Admin UI - Create/Edit Form ✅ CRITICAL

**Purpose**: Form to register new SPs or edit existing ones.

**Implementation**:

```go
// In server/ui_saml.go

func (s *IDPServer) handleNewSAMLSP(w http.ResponseWriter, r *http.Request) {
    // Return 404 if SAML is not enabled
    if !s.enableSAML {
        writeHTTPError(w, r, http.StatusNotFound, ecNotFound,
            "SAML is not enabled", nil)
        return
    }

    if r.Method == "GET" {
        if err := s.renderSAMLSPForm(w, samlSPDisplayData{IsNew: true}); err != nil {
            writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
                "failed to render form", err)
        }
        return
    }

    if r.Method == "POST" {
        if err := r.ParseForm(); err != nil {
            writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest,
                "failed to parse form", err)
            return
        }

        entityID := strings.TrimSpace(r.FormValue("entity_id"))
        name := strings.TrimSpace(r.FormValue("name"))
        acsURLsText := strings.TrimSpace(r.FormValue("acs_urls"))
        acsURLs := splitLines(acsURLsText)

        baseData := samlSPDisplayData{
            IsNew:    true,
            EntityID: entityID,
            Name:     name,
            ACSURLs:  acsURLs,
        }

        // Validation
        if entityID == "" {
            s.renderSAMLSPFormError(w, r, baseData, "Entity ID is required")
            return
        }
        if name == "" {
            s.renderSAMLSPFormError(w, r, baseData, "Name is required")
            return
        }
        if errMsg := validateEntityID(entityID); errMsg != "" {
            s.renderSAMLSPFormError(w, r, baseData,
                fmt.Sprintf("Invalid Entity ID: %s", errMsg))
            return
        }
        if len(acsURLs) == 0 {
            s.renderSAMLSPFormError(w, r, baseData,
                "At least one ACS URL is required")
            return
        }
        for _, url := range acsURLs {
            if errMsg := validateACSURL(url); errMsg != "" {
                s.renderSAMLSPFormError(w, r, baseData,
                    fmt.Sprintf("Invalid ACS URL '%s': %s", url, errMsg))
                return
            }
        }

        // Check for duplicate Entity ID
        s.mu.Lock()
        if _, exists := s.samlServiceProviders[entityID]; exists {
            s.mu.Unlock()
            s.renderSAMLSPFormError(w, r, baseData,
                "Entity ID already registered")
            return
        }

        // Create new SP
        newSP := &SAMLServiceProvider{
            EntityID: entityID,
            Name:     name,
            ACSURLs:  acsURLs,
        }

        if s.samlServiceProviders == nil {
            s.samlServiceProviders = make(map[string]*SAMLServiceProvider)
        }
        s.samlServiceProviders[entityID] = newSP
        err := s.storeSAMLServiceProvidersLocked()
        s.mu.Unlock()

        if err != nil {
            slog.Error("SAML SP create: failed to persist", slog.Any("error", err))
            s.renderSAMLSPFormError(w, r, baseData, "Failed to save SP")
            return
        }

        s.renderSAMLSPFormSuccess(w, r, baseData,
            "Service Provider registered successfully!")
        return
    }

    writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest,
        "method not allowed", nil)
}

func (s *IDPServer) handleEditSAMLSP(w http.ResponseWriter, r *http.Request) {
    // Return 404 if SAML is not enabled
    if !s.enableSAML {
        writeHTTPError(w, r, http.StatusNotFound, ecNotFound,
            "SAML is not enabled", nil)
        return
    }

    // Extract Entity ID from URL path
    entityID := strings.TrimPrefix(r.URL.Path, "/saml/sp/edit/")
    entityID, err := url.QueryUnescape(entityID)
    if err != nil || entityID == "" {
        writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest,
            "invalid Entity ID", err)
        return
    }

    s.mu.Lock()
    sp, exists := s.samlServiceProviders[entityID]
    s.mu.Unlock()

    if !exists {
        writeHTTPError(w, r, http.StatusNotFound, ecNotFound,
            "SP not found", nil)
        return
    }

    if r.Method == "GET" {
        data := samlSPDisplayData{
            EntityID: sp.EntityID,
            Name:     sp.Name,
            ACSURLs:  sp.ACSURLs,
            IsEdit:   true,
        }
        if err := s.renderSAMLSPForm(w, data); err != nil {
            writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
                "failed to render form", err)
        }
        return
    }

    if r.Method == "POST" {
        action := r.FormValue("action")

        if action == "delete" {
            s.mu.Lock()
            delete(s.samlServiceProviders, entityID)
            err := s.storeSAMLServiceProvidersLocked()
            s.mu.Unlock()

            if err != nil {
                slog.Error("SAML SP delete: failed to persist", slog.Any("error", err))
                // Restore SP on error
                s.mu.Lock()
                s.samlServiceProviders[entityID] = sp
                s.mu.Unlock()

                baseData := samlSPDisplayData{
                    EntityID: sp.EntityID,
                    Name:     sp.Name,
                    ACSURLs:  sp.ACSURLs,
                    IsEdit:   true,
                }
                s.renderSAMLSPFormError(w, r, baseData,
                    "Failed to delete SP. Please try again.")
                return
            }

            http.Redirect(w, r, "/saml/sp", http.StatusSeeOther)
            return
        }

        // Handle update
        if err := r.ParseForm(); err != nil {
            writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest,
                "failed to parse form", err)
            return
        }

        name := strings.TrimSpace(r.FormValue("name"))
        acsURLsText := strings.TrimSpace(r.FormValue("acs_urls"))
        acsURLs := splitLines(acsURLsText)

        baseData := samlSPDisplayData{
            EntityID: entityID,
            Name:     name,
            ACSURLs:  acsURLs,
            IsEdit:   true,
        }

        // Validation
        if name == "" {
            s.renderSAMLSPFormError(w, r, baseData, "Name is required")
            return
        }
        if len(acsURLs) == 0 {
            s.renderSAMLSPFormError(w, r, baseData,
                "At least one ACS URL is required")
            return
        }
        for _, url := range acsURLs {
            if errMsg := validateACSURL(url); errMsg != "" {
                s.renderSAMLSPFormError(w, r, baseData,
                    fmt.Sprintf("Invalid ACS URL '%s': %s", url, errMsg))
                return
            }
        }

        // Update SP
        s.mu.Lock()
        s.samlServiceProviders[entityID].Name = name
        s.samlServiceProviders[entityID].ACSURLs = acsURLs
        err := s.storeSAMLServiceProvidersLocked()
        s.mu.Unlock()

        if err != nil {
            slog.Error("SAML SP update: failed to persist", slog.Any("error", err))
            s.renderSAMLSPFormError(w, r, baseData, "Failed to update SP")
            return
        }

        s.renderSAMLSPFormSuccess(w, r, baseData,
            "Service Provider updated successfully!")
        return
    }

    writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest,
        "method not allowed", nil)
}

// Helper functions

func (s *IDPServer) renderSAMLSPForm(w http.ResponseWriter, data samlSPDisplayData) error {
    var buf bytes.Buffer
    if err := samlSPEditTmpl.Execute(&buf, data); err != nil {
        return err
    }
    if _, err := buf.WriteTo(w); err != nil {
        return err
    }
    return nil
}

func (s *IDPServer) renderSAMLSPFormError(w http.ResponseWriter, r *http.Request,
    data samlSPDisplayData, errorMsg string) {
    data.Error = errorMsg
    if err := s.renderSAMLSPForm(w, data); err != nil {
        writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
            "failed to render form", err)
    }
}

func (s *IDPServer) renderSAMLSPFormSuccess(w http.ResponseWriter, r *http.Request,
    data samlSPDisplayData, successMsg string) {
    data.Success = successMsg
    if err := s.renderSAMLSPForm(w, data); err != nil {
        writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
            "failed to render form", err)
    }
}

func validateEntityID(entityID string) string {
    u, err := url.Parse(entityID)
    if err != nil || u.Scheme == "" {
        return "must be a valid URI with a scheme"
    }
    return ""
}

func validateACSURL(acsURL string) string {
    u, err := url.Parse(acsURL)
    if err != nil || u.Scheme == "" {
        return "must be a valid URL with a scheme"
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return "must use http or https scheme"
    }
    if u.Host == "" {
        return "must have a host"
    }
    return ""
}

func splitLines(text string) []string {
    lines := strings.Split(text, "\n")
    var result []string
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line != "" {
            result = append(result, line)
        }
    }
    return result
}
```

**Template** (`server/ui-saml-edit.html`):

```html
{{template "header" .}}

{{if .IsNew}}
<h1>Register New SAML Service Provider</h1>
{{else}}
<h1>Edit SAML Service Provider</h1>
{{end}}

{{if .Success}}
<div class="success">{{.Success}}</div>
{{end}}

{{if .Error}}
<div class="error">{{.Error}}</div>
{{end}}

<form method="POST">
    <div class="form-group">
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" value="{{.Name}}" required>
        <small>Human-readable name for this service provider</small>
    </div>

    {{if .IsNew}}
    <div class="form-group">
        <label for="entity_id">Entity ID:</label>
        <input type="text" id="entity_id" name="entity_id" value="{{.EntityID}}"
               required placeholder="https://app.example.com/saml">
        <small>Unique identifier for the SP (usually a URL)</small>
    </div>
    {{else}}
    <div class="form-group">
        <label>Entity ID:</label>
        <code>{{.EntityID}}</code>
        <small>Cannot be changed after creation</small>
    </div>
    {{end}}

    <div class="form-group">
        <label for="acs_urls">ACS URLs (one per line):</label>
        <textarea id="acs_urls" name="acs_urls" rows="5" required>{{range .ACSURLs}}{{.}}
{{end}}</textarea>
        <small>Assertion Consumer Service URLs where responses will be sent</small>
    </div>

    <div class="form-actions">
        {{if .IsNew}}
        <button type="submit">Register SP</button>
        {{else}}
        <button type="submit">Update SP</button>
        <button type="submit" name="action" value="delete"
                onclick="return confirm('Are you sure you want to delete this SP?')">
            Delete SP
        </button>
        {{end}}
        <a href="/saml/sp">Cancel</a>
    </div>
</form>

</body>
</html>
```

### 5. SSO Flow Integration ✅ CRITICAL

**Purpose**: Validate SP Entity ID and ACS URL during SSO flow.

**Implementation**:

```go
// In server/saml.go - Update serveSAMLSSO()

func (s *IDPServer) serveSAMLSSO(w http.ResponseWriter, r *http.Request) {
    // ... existing Funnel check and AuthnRequest parsing ...

    // SP verification can be disabled for development/testing
    if !s.disableSAMLSPVerification {
        // Extract SP Entity ID from AuthnRequest
        spEntityID := authnRequest.Issuer.Value
        if spEntityID == "" {
            slog.Warn("SAML SSO: missing Issuer in AuthnRequest",
                "remote_addr", r.RemoteAddr)
            s.sendSAMLError(w, "", "", "",
                "urn:oasis:names:tc:SAML:2.0:status:Requester",
                "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
                "Missing Issuer in AuthnRequest")
            return
        }

        // Lookup SP in registry
        s.mu.Lock()
        sp, registered := s.samlServiceProviders[spEntityID]
        s.mu.Unlock()

        if !registered {
            slog.Warn("SAML SSO: unregistered SP attempted authentication",
                "entity_id", spEntityID,
                "remote_addr", r.RemoteAddr)
            s.sendSAMLError(w, authnRequest.AssertionConsumerServiceURL,
                authnRequest.ID, relayState,
                "urn:oasis:names:tc:SAML:2.0:status:Responder",
                "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
                "Service Provider not registered")
            return
        }

        // Validate ACS URL matches registered URLs
        acsURL := authnRequest.AssertionConsumerServiceURL
        if acsURL == "" {
            slog.Warn("SAML SSO: missing AssertionConsumerServiceURL",
                "entity_id", spEntityID,
                "remote_addr", r.RemoteAddr)
            s.sendSAMLError(w, "", authnRequest.ID, relayState,
                "urn:oasis:names:tc:SAML:2.0:status:Requester",
                "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
                "Missing AssertionConsumerServiceURL in AuthnRequest")
            return
        }

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
                "registered_acs", sp.ACSURLs)
            s.sendSAMLError(w, acsURL, authnRequest.ID, relayState,
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

    // ... continue with existing WhoIs and response generation ...
}
```

### 6. UI Route Registration ✅ IMPORTANT

**Purpose**: Mount SAML SP management routes in the existing UI.

**Implementation**:

```go
// In server/server.go - Update handleUI()

func (s *IDPServer) handleUI(w http.ResponseWriter, r *http.Request) {
    if isFunnelRequest(r) {
        writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied,
            "not available over funnel", nil)
        return
    }

    access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
    if !ok {
        writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied,
            "application capability not found", nil)
        return
    }

    if !access.allowAdminUI {
        writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied,
            "application capability not granted", nil)
        return
    }

    // OAuth client routes
    switch r.URL.Path {
    case "/":
        s.handleClientsList(w, r)
        return
    case "/new":
        s.handleNewClient(w, r)
        return
    case "/style.css":
        http.ServeContent(w, r, "ui-style.css", processStart,
            strings.NewReader(styleCSS))
        return
    }

    if strings.HasPrefix(r.URL.Path, "/edit/") {
        s.handleEditClient(w, r)
        return
    }

    // SAML SP routes
    switch r.URL.Path {
    case "/saml/sp":
        s.handleSAMLSPList(w, r)
        return
    case "/saml/sp/new":
        s.handleNewSAMLSP(w, r)
        return
    }

    if strings.HasPrefix(r.URL.Path, "/saml/sp/edit/") {
        s.handleEditSAMLSP(w, r)
        return
    }

    writeHTTPError(w, r, http.StatusNotFound, ecNotFound, "not found", nil)
}
```

**Update header template** (`server/ui-header.html`):

```html
<!DOCTYPE html>
<html>
  <head>
    <title>tsidp Admin</title>
    <link rel="stylesheet" href="/style.css" />
  </head>
  <body>
    <nav>
      <a href="/">OAuth Clients</a>
      <a href="/saml/sp">SAML SPs</a>
    </nav>
  </body>
</html>
```

**Note**: All template data structures that use the header template should include an `EnableSAML bool` field to pass SAML enablement state to templates, though the navigation link is always shown.

## Testing Strategy

### Unit Tests

Add to `server/saml_test.go`:

```go
func TestValidateEntityID(t *testing.T) {
    tests := []struct {
        name     string
        entityID string
        wantErr  bool
    }{
        {"valid https URL", "https://app.example.com/saml", false},
        {"valid http URL", "http://localhost:8080/saml", false},
        {"valid URN", "urn:example:sp:1234", false},
        {"missing scheme", "app.example.com/saml", true},
        {"empty", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validateEntityID(tt.entityID)
            if (err != "") != tt.wantErr {
                t.Errorf("validateEntityID() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestStorageRoundTrip(t *testing.T) {
    tmpDir := t.TempDir()

    // Create test SPs
    sps := map[string]*SAMLServiceProvider{
        "https://sp1.example.com/saml": {
            EntityID: "https://sp1.example.com/saml",
            Name:     "SP 1",
            ACSURLs:  []string{"https://sp1.example.com/acs"},
        },
        "https://sp2.example.com/saml": {
            EntityID: "https://sp2.example.com/saml",
            Name:     "SP 2",
            ACSURLs:  []string{
                "https://sp2.example.com/acs",
                "https://sp2.example.com/acs/backup",
            },
        },
    }

    // Create mock server and store
    srv := &IDPServer{
        stateDir:             tmpDir,
        samlServiceProviders: sps,
    }

    srv.mu.Lock()
    err := srv.storeSAMLServiceProvidersLocked()
    srv.mu.Unlock()
    if err != nil {
        t.Fatalf("storeSAMLServiceProvidersLocked() failed: %v", err)
    }

    // Load and compare
    loadedSPs, err := loadSAMLServiceProviders(tmpDir)
    if err != nil {
        t.Fatalf("loadSAMLServiceProviders() failed: %v", err)
    }

    if len(loadedSPs) != len(sps) {
        t.Errorf("loaded %d SPs, want %d", len(loadedSPs), len(sps))
    }

    for entityID, sp := range sps {
        loaded, ok := loadedSPs[entityID]
        if !ok {
            t.Errorf("SP %s not loaded", entityID)
            continue
        }
        if loaded.Name != sp.Name {
            t.Errorf("SP %s: name = %s, want %s", entityID, loaded.Name, sp.Name)
        }
        if !reflect.DeepEqual(loaded.ACSURLs, sp.ACSURLs) {
            t.Errorf("SP %s: ACS URLs mismatch", entityID)
        }
    }
}
```

### Integration Tests

Add to `server/saml_test.go`:

```go
func TestSAMLSPRegistryIntegration(t *testing.T) {
    // Setup test server with SAML enabled
    srv := setupTestServer(t, true /* enableSAML */)

    // Register an SP via API (simulating UI form submission)
    form := url.Values{
        "entity_id": {"https://test-sp.example.com/saml"},
        "name":      {"Test SP"},
        "acs_urls":  {"https://test-sp.example.com/acs\nhttps://test-sp.example.com/acs2"},
    }

    req := httptest.NewRequest("POST", "/saml/sp/new", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    rec := httptest.NewRecorder()

    srv.handleNewSAMLSP(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("handleNewSAMLSP() status = %d, want 200", rec.Code)
    }

    // Verify SP is registered
    srv.mu.Lock()
    sp, exists := srv.samlServiceProviders["https://test-sp.example.com/saml"]
    srv.mu.Unlock()

    if !exists {
        t.Fatal("SP not registered")
    }
    if sp.Name != "Test SP" {
        t.Errorf("SP name = %s, want Test SP", sp.Name)
    }
    if len(sp.ACSURLs) != 2 {
        t.Errorf("SP has %d ACS URLs, want 2", len(sp.ACSURLs))
    }
}

func TestSAMLSSOValidation(t *testing.T) {
    srv := setupTestServer(t, true /* enableSAML */)

    // Register test SP
    srv.mu.Lock()
    srv.samlServiceProviders["https://test-sp.example.com/saml"] = &SAMLServiceProvider{
        EntityID: "https://test-sp.example.com/saml",
        Name:     "Test SP",
        ACSURLs:  []string{"https://test-sp.example.com/acs"},
    }
    srv.mu.Unlock()

    tests := []struct {
        name       string
        entityID   string
        acsURL     string
        wantStatus string
    }{
        {
            name:       "registered SP with valid ACS",
            entityID:   "https://test-sp.example.com/saml",
            acsURL:     "https://test-sp.example.com/acs",
            wantStatus: "Success",
        },
        {
            name:       "unregistered SP",
            entityID:   "https://unknown-sp.example.com/saml",
            acsURL:     "https://unknown-sp.example.com/acs",
            wantStatus: "RequestDenied",
        },
        {
            name:       "registered SP with invalid ACS",
            entityID:   "https://test-sp.example.com/saml",
            acsURL:     "https://attacker.com/acs",
            wantStatus: "RequestDenied",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create mock AuthnRequest
            authnReq := createTestAuthnRequest(tt.entityID, tt.acsURL)

            req := httptest.NewRequest("GET", "/saml/sso?SAMLRequest="+encodeAuthnRequest(authnReq), nil)
            rec := httptest.NewRecorder()

            srv.serveSAMLSSO(rec, req)

            // Parse response and check status
            status := extractSAMLStatus(rec.Body.String())
            if !strings.Contains(status, tt.wantStatus) {
                t.Errorf("got status %s, want %s", status, tt.wantStatus)
            }
        })
    }
}

// Helper function to create a test AuthnRequest with specified entity ID and ACS URL
func createTestAuthnRequest(entityID, acsURL string) *saml.AuthnRequest {
    return &saml.AuthnRequest{
        ID: "test_" + uuid.New().String(),
        Issuer: &saml.Issuer{
            Value: entityID,
        },
        AssertionConsumerServiceURL: acsURL,
    }
}

// Helper function to encode an AuthnRequest for use in URL parameters
func encodeAuthnRequest(req *saml.AuthnRequest) string {
    // Marshal to XML
    xmlBytes, _ := xml.Marshal(req)

    // Deflate compress
    var b bytes.Buffer
    w, _ := flate.NewWriter(&b, flate.DefaultCompression)
    w.Write(xmlBytes)
    w.Close()

    // Base64 encode
    return base64.StdEncoding.EncodeToString(b.Bytes())
}

// Helper function to extract SAML status from response HTML/XML
func extractSAMLStatus(body string) string {
    // This is a simplified parser - adjust based on actual response format
    if strings.Contains(body, "urn:oasis:names:tc:SAML:2.0:status:Success") {
        return "Success"
    }
    if strings.Contains(body, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied") {
        return "RequestDenied"
    }
    return "Unknown"
}
```

### Manual Testing

1. **Start tsidp with SAML enabled**:

   ```bash
   go run . -dir /tmp/tsidp-test -hostname test-idp -experimental-enable-saml
   ```

2. **Access admin UI**: Navigate to `https://test-idp.your-tailnet.ts.net/`

3. **Register a test SP**:

   - Click "SAML SPs" tab
   - Click "Register New SP"
   - Fill in form:
     - Name: Test Service Provider
     - Entity ID: http://localhost:58080/saml
     - ACS URLs: http://localhost:58080/saml/acs
   - Submit form

4. **Test with registered SP using verifier-saml**:

   ```bash
   go run cmd/verifier-saml/verifier-saml.go \
     -v \
     -sp-entity-id http://localhost:58080/saml \
     -idp-metadata-url https://test-idp.your-tailnet.ts.net/saml/metadata
   ```

   - Follow browser link from verifier-saml
   - Verify successful authentication

5. **Test validation with unregistered SP**:

   ```bash
   go run cmd/verifier-saml/verifier-saml.go \
     -v \
     -sp-entity-id http://localhost:58080/unregistered-sp \
     -idp-metadata-url https://test-idp.your-tailnet.ts.net/saml/metadata
   ```

   - Follow browser link
   - Verify RequestDenied error response

6. **Test validation with mismatched ACS URL**:
   - Edit SP in admin UI to change ACS URL to something different
   - Try SSO with verifier-saml using original entity ID
   - Verify RequestDenied error for ACS URL mismatch

## Implementation Checklist

### Phase 1: Data Model & Storage

- [ ] Add `SAMLServiceProvider` struct to `server/saml.go`
- [ ] Implement `storeSAMLServiceProvidersLocked()` in `server/saml.go`
- [ ] Implement `loadSAMLServiceProviders()` in `server/saml.go`
- [ ] Add `samlServiceProviders map[string]*SAMLServiceProvider` to IDPServer
- [ ] Add `disableSAMLSPVerification bool` to IDPServer
- [ ] Add `-experimental-disable-saml-sp-verification` flag to `tsidp-server.go`
- [ ] Update `scripts/docker/run.sh` to support `TSIDP_EXPERIMENTAL_DISABLE_SAML_SP_VERIFICATION` env var
- [ ] Update `README.md` to document new flag and environment variable
- [ ] Update `loadState()` to load SP registry on startup
- [ ] Write unit tests for storage round-trip in `server/saml_test.go`

### Phase 2: Admin UI Templates

- [ ] Create `server/ui-saml-list.html` template
- [ ] Create `server/ui-saml-edit.html` template
- [ ] Update `server/ui-header.html` to add SAML SPs navigation link
- [ ] Add template parsing in `ui_saml.go`

### Phase 3: Admin UI Handlers

- [ ] Create `server/ui_saml.go`
- [ ] Implement `samlSPDisplayData` struct
- [ ] Implement `handleSAMLSPList()`
- [ ] Implement `handleNewSAMLSP()` (GET and POST)
- [ ] Implement `handleEditSAMLSP()` (GET, POST update, POST delete)
- [ ] Implement validation helpers: `validateEntityID()` (with empty name check), `validateACSURL()`, `splitLines()`
- [ ] Implement form rendering helpers

### Phase 4: Route Registration

- [ ] Update `handleUI()` in `server/server.go` to route SAML SP requests
- [ ] Add conditional routing based on `enableSAML` flag
- [ ] Test UI navigation between OAuth and SAML sections

### Phase 5: SSO Flow Integration

- [ ] Update `serveSAMLSSO()` in `server/saml.go`:
  - [ ] Add check for `disableSAMLSPVerification` flag
  - [ ] Add SP Entity ID lookup
  - [ ] Add ACS URL validation
  - [ ] Add appropriate SAML error responses (use RequestDenied status)
  - [ ] Add slog.Warn logging for all SP verification failures
- [ ] Write integration tests for SSO validation in `server/saml_test.go`
- [ ] Add test helper functions: `createTestAuthnRequest()`, `encodeAuthnRequest()`, `extractSAMLStatus()`

### Phase 6: Testing & Documentation

- [ ] Write unit tests for validation functions
- [ ] Write unit tests for storage
- [ ] Write integration tests for UI handlers
- [ ] Write integration tests for SSO validation
- [ ] Manual testing with verifier-saml

## Success Criteria

The SP registry implementation is complete when:

1. ✅ SPs can be registered via admin UI with Entity ID and ACS URLs
2. ✅ SPs are persisted to `saml-service-providers.json` in stateDir
3. ✅ SP list displays all registered SPs with proper formatting
4. ✅ SP edit/delete functionality works correctly
5. ✅ SSO flow validates Entity ID against registry
6. ✅ SSO flow validates ACS URL against registered URLs
7. ✅ Unregistered SPs receive RequestDenied SAML error
8. ✅ Invalid ACS URLs receive RequestDenied SAML error
9. ✅ All SP verification failures are logged with slog.Warn including context (entity_id, remote_addr, etc.)
10. ✅ All unit and integration tests pass
11. ✅ verifier-saml successfully authenticates with registered SP
12. ✅ verifier-saml fails authentication when SP is not registered

## Security Considerations

1. **SP Validation**:

   - Entity ID must exist in registry before SSO proceeds
   - ACS URL must exactly match one of the registered URLs (no partial matching)
   - Log all unauthorized access attempts with Entity ID and source IP

2. **Admin UI Access**:

   - Reuse existing `allowAdminUI` capability check
   - Admin UI blocked over Funnel (Tailnet-only access)
   - No authentication bypass via URL manipulation

3. **Data Persistence**:

   - File permissions: 0600 (owner read/write only)
   - JSON file location: inside stateDir (user-controlled location)
   - No sensitive data stored (no secrets or credentials)

4. **Input Validation**:

   - Entity ID: Must be valid URI with scheme
   - ACS URLs: Must be valid HTTP/HTTPS URLs with host
   - Prevent duplicate Entity IDs
   - Sanitize all form inputs

5. **Deferred Security (Future Enhancements)**:
   - AuthnRequest signature verification (Tailnet trust model defers this)
   - Rate limiting on failed SP validations
   - Audit log of SP registration changes

## Future Enhancements

After the core SP registry implementation:

1. **Metadata Import** - Parse and import SP metadata XML

   - Add upload field to UI form
   - Parse XML to extract Entity ID, ACS URLs, certificates
   - Pre-fill form fields from parsed metadata

2. **AuthnRequest Signature Verification** - Validate signed requests

   - Store SP certificates in registry
   - Verify AuthnRequest signatures in SSO handler
   - Required for Funnel mode support

3. **Audit Logging** - Track SP configuration changes

   - Log SP registration, updates, deletions
   - Track which admin made changes
   - Export audit log for compliance

4. **Per-SP Attribute Mapping** - Custom attributes per SP
   - Add attribute configuration to SP registry
   - Override default attributes based on SP
   - Supports enhancement #6 in main plan
