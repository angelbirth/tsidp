// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

//go:embed ui-saml-list.html
var samlListHTML string

//go:embed ui-saml-edit.html
var samlEditHTML string

var samlSPListTmpl = template.Must(headerTmpl.New("saml-list").Parse(samlListHTML))
var samlSPEditTmpl = template.Must(headerTmpl.New("saml-edit").Funcs(template.FuncMap{
	"urlquery": url.QueryEscape,
}).Parse(samlEditHTML))

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

// handleSAMLSPList displays all registered SPs
func (s *IDPServer) handleSAMLSPList(w http.ResponseWriter, r *http.Request) {
	// Check if SAML is enabled
	if !s.enableSAML {
		var buf bytes.Buffer
		if err := samlSPListTmpl.Execute(&buf, samlSPListData{SAMLDisabled: true}); err != nil {
			writeHTTPError(w, r, http.StatusInternalServerError, ecServerError,
				"failed to render SP list", err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// handleNewSAMLSP handles creating a new SP
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
		for _, acsURL := range acsURLs {
			if errMsg := validateACSURL(acsURL); errMsg != "" {
				s.renderSAMLSPFormError(w, r, baseData,
					fmt.Sprintf("Invalid ACS URL '%s': %s", acsURL, errMsg))
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

		slog.Info("SAML SP registered", "entity_id", entityID, "name", name)
		s.renderSAMLSPFormSuccess(w, r, baseData,
			"Service Provider registered successfully!")
		return
	}

	writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest,
		"method not allowed", nil)
}

// handleEditSAMLSP handles editing and deleting an SP
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
		if err := r.ParseForm(); err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest,
				"failed to parse form", err)
			return
		}

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

			slog.Info("SAML SP deleted", "entity_id", entityID)
			http.Redirect(w, r, "/saml/sp", http.StatusSeeOther)
			return
		}

		// Handle update
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
		for _, acsURL := range acsURLs {
			if errMsg := validateACSURL(acsURL); errMsg != "" {
				s.renderSAMLSPFormError(w, r, baseData,
					fmt.Sprintf("Invalid ACS URL '%s': %s", acsURL, errMsg))
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

		slog.Info("SAML SP updated", "entity_id", entityID, "name", name)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
	if entityID == "" {
		return "entity ID cannot be empty"
	}
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
