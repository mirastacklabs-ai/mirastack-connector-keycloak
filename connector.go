// Package main implements the Keycloak OIDC auth connector for MIRASTACK.
//
// Authentication flow (Resource Owner Password Credentials):
//  1. POST {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token
//     with grant_type=password, client_id, client_secret, username (email), password.
//  2. Decode the returned JWT access token to extract identity claims:
//     sub → ExternalSubject, email, preferred_username, name, realm_access.roles.
//  3. Map Keycloak realm roles to Mirastack roles via KEYCLOAK_ROLE_MAPPING JSON.
//  4. Return a populated AuthnResult to the engine.
//
// The connector does NOT perform the OIDC discovery call for ROPC — it
// constructs the token endpoint URL directly from KEYCLOAK_URL and KEYCLOAK_REALM.
// This avoids an extra round-trip and eliminates a network dependency at startup.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	connectorv1 "github.com/mirastacklabs-ai/mirastack-connector-sdk-go/gen/connectorv1"
	"go.uber.org/zap"

	mirastack "github.com/mirastacklabs-ai/mirastack-connector-sdk-go"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// KeycloakConfig holds the fully-resolved runtime configuration for the
// Keycloak connector. All fields are loaded from environment variables.
type KeycloakConfig struct {
	// KeycloakURL is the base URL of the Keycloak server, e.g.
	// "https://keycloak.corp.local:8443".
	KeycloakURL string
	// Realm is the Keycloak realm name, e.g. "mirastack".
	Realm string
	// ClientID is the OIDC client identifier registered in the realm.
	ClientID string
	// ClientSecret is the OIDC client secret.
	ClientSecret string
	// RoleMapping is a JSON string mapping Keycloak realm role names to
	// Mirastack roles (operator | engineer | admin).
	// Example: {"keycloak-admin":"admin","platform-engineer":"engineer"}
	RoleMapping string
	// DefaultRole is used when no realm role mapping resolves.
	DefaultRole string
	// TLSSkipVerify disables TLS certificate verification. Useful for
	// internal deployments with self-signed certificates.
	TLSSkipVerify bool
	// TimeoutSec is the per-request HTTP timeout in seconds.
	TimeoutSec int
	// ProviderName is the canonical provider name reported to the engine.
	ProviderName string
}

// ---------------------------------------------------------------------------
// Connector struct
// ---------------------------------------------------------------------------

// KeycloakConnector is the MIRASTACK connector for Keycloak OIDC.
// It implements mirastack.Plugin, mirastack.IdentityProviderAware, and
// connectorv1.IdentityProviderServiceServer.
type KeycloakConnector struct {
	cfg     KeycloakConfig
	version string
	logger  *zap.Logger

	mu      sync.RWMutex // protects cfg for runtime config updates
	client  *http.Client
	roleMap map[string]string // parsed from cfg.RoleMapping JSON
}

// NewKeycloakConnector creates a connector with the given configuration.
// A connectivity probe is performed at construction to surface misconfiguration
// early (verifies the Keycloak token endpoint is reachable).
func NewKeycloakConnector(cfg KeycloakConfig, version string, logger *zap.Logger) (*KeycloakConnector, error) {
	c := &KeycloakConnector{
		cfg:     cfg,
		version: version,
		logger:  logger.Named("keycloak"),
	}
	c.client = c.buildHTTPClient(cfg)

	parsed, err := parseRoleMapping(cfg.RoleMapping)
	if err != nil {
		return nil, fmt.Errorf("keycloak: invalid KEYCLOAK_ROLE_MAPPING JSON: %w", err)
	}
	c.roleMap = parsed

	// Connectivity probe — HEAD to the token endpoint.
	tokenURL := c.tokenURL()
	probeReq, err := http.NewRequestWithContext(context.Background(), http.MethodHead, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: build probe request: %w", err)
	}
	resp, err := c.client.Do(probeReq)
	if err != nil {
		return nil, fmt.Errorf("keycloak: connectivity probe to %s failed: %w", tokenURL, err)
	}
	resp.Body.Close()

	return c, nil
}

// buildHTTPClient constructs a *http.Client respecting TLS and timeout settings.
func (c *KeycloakConnector) buildHTTPClient(cfg KeycloakConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec // configurable per deployment
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
	}
}

// tokenURL returns the OIDC token endpoint for the configured realm.
func (c *KeycloakConnector) tokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.KeycloakURL, "/"), c.cfg.Realm)
}

// ---------------------------------------------------------------------------
// mirastack.Plugin interface
// ---------------------------------------------------------------------------

// Info returns plugin metadata. The Metadata map signals to the engine that
// this connector implements the IdentityProvider extension point.
func (c *KeycloakConnector) Info() *mirastack.PluginInfo {
	return &mirastack.PluginInfo{
		Name:        "mirastack-connector-keycloak",
		Version:     c.version,
		Description: "Keycloak OIDC auth connector for MIRASTACK (OSS)",
		Metadata: map[string]string{
			"identity_provider":      "true",
			"identity_provider_type": "oidc",
		},
	}
}

// Schema returns an empty schema — connectors do not contribute to the tool
// catalog and have no actions.
func (c *KeycloakConnector) Schema() *mirastack.PluginSchema {
	return &mirastack.PluginSchema{}
}

// Execute is not called for connectors.
func (c *KeycloakConnector) Execute(_ context.Context, _ *mirastack.ExecuteRequest) (*mirastack.ExecuteResponse, error) {
	return nil, fmt.Errorf("keycloak connector does not support Execute")
}

// HealthCheck probes the Keycloak token endpoint and returns plugin health.
func (c *KeycloakConnector) HealthCheck(_ context.Context) error {
	c.mu.RLock()
	tokenURL := c.tokenURL()
	client := c.client
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, tokenURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	resp.Body.Close()
	return nil
}

// ConfigUpdated handles runtime config changes delivered by the engine.
func (c *KeycloakConnector) ConfigUpdated(_ context.Context, config map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if v := config["keycloak_url"]; v != "" {
		c.cfg.KeycloakURL = v
	}
	if v := config["realm"]; v != "" {
		c.cfg.Realm = v
	}
	if v := config["client_id"]; v != "" {
		c.cfg.ClientID = v
	}
	if v := config["client_secret"]; v != "" {
		c.cfg.ClientSecret = v
	}
	if v := config["role_mapping"]; v != "" {
		parsed, err := parseRoleMapping(v)
		if err != nil {
			return fmt.Errorf("keycloak: invalid role_mapping JSON: %w", err)
		}
		c.roleMap = parsed
		c.cfg.RoleMapping = v
	}
	if v := config["default_role"]; v != "" {
		c.cfg.DefaultRole = v
	}
	// Rebuild HTTP client if TLS settings changed.
	c.client = c.buildHTTPClient(c.cfg)
	c.logger.Info("configuration updated")
	return nil
}

// ---------------------------------------------------------------------------
// mirastack.IdentityProviderAware interface
// ---------------------------------------------------------------------------

// AsIdentityProvider returns the connector itself as the
// IdentityProviderServiceServer implementation.
func (c *KeycloakConnector) AsIdentityProvider() connectorv1.IdentityProviderServiceServer {
	return &keycloakIdentityProviderServer{connector: c}
}

type keycloakIdentityProviderServer struct {
	connector *KeycloakConnector
}

func (s *keycloakIdentityProviderServer) Authenticate(ctx context.Context, req *connectorv1.AuthnRequest) (*connectorv1.AuthnResult, error) {
	return s.connector.Authenticate(ctx, req)
}

func (s *keycloakIdentityProviderServer) HealthCheck(ctx context.Context, _ *connectorv1.HealthCheckRequest) (*connectorv1.HealthCheckResponse, error) {
	err := s.connector.HealthCheck(ctx)
	if err != nil {
		return &connectorv1.HealthCheckResponse{Healthy: false, Detail: err.Error()}, nil
	}
	return &connectorv1.HealthCheckResponse{Healthy: true, Detail: "Keycloak token endpoint reachable"}, nil
}

// ---------------------------------------------------------------------------
// connectorv1.IdentityProviderServiceServer interface
// ---------------------------------------------------------------------------

// keycloakTokenResponse is the JSON structure returned by the Keycloak token
// endpoint on a successful ROPC grant.
type keycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// keycloakErrorResponse is the JSON body returned by Keycloak on failure.
type keycloakErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// keycloakClaims contains the JWT claims we extract from the access token.
type keycloakClaims struct {
	Sub               string                 `json:"sub"`
	Email             string                 `json:"email"`
	PreferredUsername string                 `json:"preferred_username"`
	Name              string                 `json:"name"`
	RealmAccess       map[string]interface{} `json:"realm_access"`
	jwt.RegisteredClaims
}

// Authenticate implements the OIDC ROPC flow against Keycloak.
func (c *KeycloakConnector) Authenticate(_ context.Context, req *connectorv1.AuthnRequest) (*connectorv1.AuthnResult, error) {
	c.mu.RLock()
	cfg := c.cfg
	client := c.client
	roleMap := c.roleMap
	c.mu.RUnlock()

	if req.Email == "" || req.Password == "" {
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonInvalidCredentials,
			Message: "email and password are required",
		}, nil
	}

	// Step 1 — ROPC token request.
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(cfg.KeycloakURL, "/"), cfg.Realm)

	formData := url.Values{
		"grant_type":    {"password"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"username":      {req.Email},
		"password":      {req.Password},
		"scope":         {"openid email profile"},
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		c.logger.Error("failed to build token request", zap.Error(err))
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: "internal error building auth request",
		}, nil
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(httpReq)
	if err != nil {
		c.logger.Warn("Keycloak token endpoint unreachable", zap.Error(err))
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: fmt.Sprintf("cannot reach Keycloak: %v", err),
		}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB safety cap
	if err != nil {
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: "failed to read Keycloak response",
		}, nil
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		var errResp keycloakErrorResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil {
			switch errResp.Error {
			case "invalid_grant":
				return &connectorv1.AuthnResult{
					Reason:  connectorv1.AuthnReasonInvalidCredentials,
					Message: errResp.ErrorDescription,
				}, nil
			case "account_disabled":
				return &connectorv1.AuthnResult{
					Reason:  connectorv1.AuthnReasonUserDeactivated,
					Message: errResp.ErrorDescription,
				}, nil
			}
		}
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonInvalidCredentials,
			Message: "authentication rejected by Keycloak",
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("unexpected Keycloak response", zap.Int("status", resp.StatusCode))
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: fmt.Sprintf("Keycloak returned status %d", resp.StatusCode),
		}, nil
	}

	// Step 2 — Parse the token response.
	var tokenResp keycloakTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: "failed to decode Keycloak token response",
		}, nil
	}

	// Step 3 — Decode JWT claims (no signature verification needed here —
	// we received the token directly from Keycloak over TLS; we trust the
	// source, not the token itself as a bearer credential).
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var claims keycloakClaims
	if _, _, err := parser.ParseUnverified(tokenResp.AccessToken, &claims); err != nil {
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: "failed to decode JWT claims",
		}, nil
	}

	// Step 4 — Map realm roles.
	role := mapKeycloakRole(claims.RealmAccess, roleMap, cfg.DefaultRole)

	username := claims.PreferredUsername
	if username == "" {
		username = deriveUsernameFromEmail(req.Email)
	}
	displayName := claims.Name
	if displayName == "" {
		displayName = username
	}

	return &connectorv1.AuthnResult{
		Reason: connectorv1.AuthnReasonOK,
		User: &connectorv1.AuthnUser{
			ExternalSubject: claims.Sub,
			Email:           claims.Email,
			Username:        username,
			DisplayName:     displayName,
			Role:            role,
			ProviderName:    cfg.ProviderName,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Role mapping
// ---------------------------------------------------------------------------

// parseRoleMapping parses the JSON role mapping string into a map.
// An empty string results in an empty map (no custom mappings).
func parseRoleMapping(raw string) (map[string]string, error) {
	if raw == "" {
		return make(map[string]string), nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mapKeycloakRole maps a Keycloak realm_access.roles list to a Mirastack role.
// It iterates realm roles, checks explicit roleMap mappings first, then falls
// back to well-known Mirastack role names. If no mapping resolves, defaultRole
// is returned.
func mapKeycloakRole(realmAccess map[string]interface{}, roleMap map[string]string, defaultRole string) string {
	rolesRaw, ok := realmAccess["roles"]
	if !ok {
		return defaultRole
	}
	roles, ok := rolesRaw.([]interface{})
	if !ok {
		return defaultRole
	}

	best := "" // highest-privilege role found so far
	for _, r := range roles {
		roleName, ok := r.(string)
		if !ok {
			continue
		}
		lower := strings.ToLower(roleName)

		// Check explicit mapping first.
		if mapped, ok := roleMap[roleName]; ok {
			if roleRank(mapped) > roleRank(best) {
				best = mapped
			}
			continue
		}
		if mapped, ok := roleMap[lower]; ok {
			if roleRank(mapped) > roleRank(best) {
				best = mapped
			}
			continue
		}

		// Well-known Mirastack role names.
		switch lower {
		case "admin", "mirastack-admin", "administrator":
			if roleRank("admin") > roleRank(best) {
				best = "admin"
			}
		case "engineer", "mirastack-engineer":
			if roleRank("engineer") > roleRank(best) {
				best = "engineer"
			}
		case "operator", "mirastack-operator":
			if roleRank("operator") > roleRank(best) {
				best = "operator"
			}
		}
	}

	if best == "" {
		return defaultRole
	}
	return best
}

// roleRank maps a Mirastack role name to a numeric rank for comparison.
func roleRank(role string) int {
	switch role {
	case "admin":
		return 3
	case "engineer":
		return 2
	case "operator":
		return 1
	}
	return 0
}

// deriveUsernameFromEmail extracts the local part of an email address.
func deriveUsernameFromEmail(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}
