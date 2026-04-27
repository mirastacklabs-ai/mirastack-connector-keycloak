package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectorv1 "github.com/mirastacklabs-ai/mirastack-connector-sdk-go/gen/connectorv1"
	"go.uber.org/zap/zaptest"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildTestServer returns an httptest.Server that responds with the given
// status and body for the token endpoint POST. All other paths return 404.
func buildTestServer(t *testing.T, statusCode int, body interface{}) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// Connectivity probe.
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.Contains(r.URL.Path, "/token") {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			enc := json.NewEncoder(w)
			_ = enc.Encode(body)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// minimalAccessToken returns a JWT with algorithm "none" whose payload encodes
// the given claims. The connector calls ParseUnverified so the signature is not
// checked — only the payload matters.
func minimalAccessToken(claims map[string]interface{}) string {
	encodeSegment := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return encodeSegment(header) + "." + encodeSegment(payload) + "."
}

func defaultTestCfg(serverURL string) KeycloakConfig {
	return KeycloakConfig{
		KeycloakURL:   serverURL,
		Realm:         "mirastack",
		ClientID:      "mira-cli",
		ClientSecret:  "secret",
		DefaultRole:   "operator",
		TLSSkipVerify: true,
		TimeoutSec:    5,
		ProviderName:  "keycloak-test",
	}
}

// newTestConnector creates a connector wired to the given test server without
// going through NewKeycloakConnector (which performs a live connectivity probe).
func newTestConnector(t *testing.T, cfg KeycloakConfig, roleMap map[string]string) *KeycloakConnector {
	t.Helper()
	logger := zaptest.NewLogger(t)
	if roleMap == nil {
		roleMap = make(map[string]string)
	}
	c := &KeycloakConnector{
		cfg:     cfg,
		logger:  logger,
		roleMap: roleMap,
	}
	c.client = c.buildHTTPClient(cfg)
	return c
}

// ---------------------------------------------------------------------------
// parseRoleMapping
// ---------------------------------------------------------------------------

func TestParseRoleMapping_Empty(t *testing.T) {
	m, err := parseRoleMapping("")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestParseRoleMapping_Valid(t *testing.T) {
	m, err := parseRoleMapping(`{"keycloak-admin":"admin","platform-engineer":"engineer"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m["keycloak-admin"] != "admin" {
		t.Errorf("keycloak-admin: got %q", m["keycloak-admin"])
	}
	if m["platform-engineer"] != "engineer" {
		t.Errorf("platform-engineer: got %q", m["platform-engineer"])
	}
}

func TestParseRoleMapping_Invalid(t *testing.T) {
	_, err := parseRoleMapping(`not json`)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// mapKeycloakRole
// ---------------------------------------------------------------------------

func TestMapKeycloakRole(t *testing.T) {
	cases := []struct {
		name     string
		roles    []interface{}
		roleMap  map[string]string
		def      string
		expected string
	}{
		{"no roles — uses default", nil, nil, "operator", "operator"},
		{"well-known admin", []interface{}{"admin"}, nil, "operator", "admin"},
		{"well-known engineer", []interface{}{"engineer"}, nil, "operator", "engineer"},
		{"mirastack-admin prefix", []interface{}{"mirastack-admin"}, nil, "operator", "admin"},
		{"explicit mapping", []interface{}{"my-admin-group"}, map[string]string{"my-admin-group": "admin"}, "operator", "admin"},
		{"highest privilege wins", []interface{}{"operator", "engineer", "admin"}, nil, "operator", "admin"},
		{"unknown — uses default", []interface{}{"some-group"}, nil, "engineer", "engineer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ra := map[string]interface{}{}
			if tc.roles != nil {
				ra["roles"] = tc.roles
			}
			rm := tc.roleMap
			if rm == nil {
				rm = make(map[string]string)
			}
			got := mapKeycloakRole(ra, rm, tc.def)
			if got != tc.expected {
				t.Errorf("mapKeycloakRole = %q; want %q", got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Authenticate — empty credentials
// ---------------------------------------------------------------------------

func TestAuthenticate_EmptyEmail(t *testing.T) {
	c := newTestConnector(t, defaultTestCfg("http://localhost"), nil)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonInvalidCredentials {
		t.Errorf("expected InvalidCredentials, got %q", result.Reason)
	}
}

func TestAuthenticate_EmptyPassword(t *testing.T) {
	c := newTestConnector(t, defaultTestCfg("http://localhost"), nil)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "user@example.com", Password: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonInvalidCredentials {
		t.Errorf("expected InvalidCredentials, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — wrong password (Keycloak 401)
// ---------------------------------------------------------------------------

func TestAuthenticate_InvalidPassword(t *testing.T) {
	ts := buildTestServer(t, http.StatusUnauthorized, keycloakErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "Invalid user credentials",
	})

	c := newTestConnector(t, defaultTestCfg(ts.URL), nil)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "alice@example.com", Password: "wrong",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonInvalidCredentials {
		t.Errorf("expected InvalidCredentials, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — deactivated account
// ---------------------------------------------------------------------------

func TestAuthenticate_AccountDisabled(t *testing.T) {
	ts := buildTestServer(t, http.StatusBadRequest, keycloakErrorResponse{
		Error:            "account_disabled",
		ErrorDescription: "User account is disabled",
	})

	c := newTestConnector(t, defaultTestCfg(ts.URL), nil)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "alice@example.com", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonUserDeactivated {
		t.Errorf("expected UserDeactivated, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — provider unreachable
// ---------------------------------------------------------------------------

func TestAuthenticate_Unreachable(t *testing.T) {
	cfg := defaultTestCfg("http://127.0.0.1:1") // nothing listening
	cfg.TimeoutSec = 1
	c := newTestConnector(t, cfg, nil)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "alice@example.com", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonProviderUnavailable {
		t.Errorf("expected ProviderUnavailable, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — success path
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "abc-123",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"name":               "Alice Smith",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"engineer"},
		},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := minimalAccessToken(claims)

	ts := buildTestServer(t, http.StatusOK, keycloakTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	c := newTestConnector(t, defaultTestCfg(ts.URL), nil)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "alice@example.com", Password: "correct",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != connectorv1.AuthnReasonOK {
		t.Errorf("expected OK, got %q (msg: %s)", result.Reason, result.Message)
	}
	if result.User == nil {
		t.Fatal("expected non-nil User on success")
	}
	if result.User.Email != "alice@example.com" {
		t.Errorf("Email: got %q", result.User.Email)
	}
	if result.User.Username != "alice" {
		t.Errorf("Username: got %q", result.User.Username)
	}
	if result.User.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName: got %q", result.User.DisplayName)
	}
	if result.User.ExternalSubject != "abc-123" {
		t.Errorf("ExternalSubject: got %q", result.User.ExternalSubject)
	}
	if result.User.Role != "engineer" {
		t.Errorf("Role: got %q, want engineer", result.User.Role)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — explicit role mapping
// ---------------------------------------------------------------------------

func TestAuthenticate_ExplicitRoleMapping(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "xyz-456",
		"email": "bob@example.com",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"platform-admin"},
		},
	}
	token := minimalAccessToken(claims)

	ts := buildTestServer(t, http.StatusOK, keycloakTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
	})

	roleMap := map[string]string{"platform-admin": "admin"}
	c := newTestConnector(t, defaultTestCfg(ts.URL), roleMap)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email: "bob@example.com", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.User == nil || result.User.Role != "admin" {
		role := ""
		if result.User != nil {
			role = result.User.Role
		}
		t.Errorf("expected admin role from explicit mapping, got %q", role)
	}
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

func TestHealthCheck_Healthy(t *testing.T) {
	ts := buildTestServer(t, http.StatusOK, nil)
	c := newTestConnector(t, defaultTestCfg(ts.URL), nil)

	resp, err := c.AsIdentityProvider().HealthCheck(context.Background(), &connectorv1.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Healthy {
		t.Errorf("expected Healthy=true, got false (detail: %s)", resp.Detail)
	}
}

func TestHealthCheck_Unreachable(t *testing.T) {
	cfg := defaultTestCfg("http://127.0.0.1:1")
	cfg.TimeoutSec = 1
	c := newTestConnector(t, cfg, nil)

	resp, err := c.AsIdentityProvider().HealthCheck(context.Background(), &connectorv1.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Healthy {
		t.Error("expected Healthy=false")
	}
}

// ---------------------------------------------------------------------------
// ConfigUpdated
// ---------------------------------------------------------------------------

func TestConfigUpdated_AppliesChanges(t *testing.T) {
	ts := buildTestServer(t, http.StatusOK, nil)
	c := newTestConnector(t, defaultTestCfg(ts.URL), nil)

	err := c.ConfigUpdated(context.Background(), map[string]string{
		"realm":        "new-realm",
		"default_role": "engineer",
	})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cfg.Realm != "new-realm" {
		t.Errorf("Realm not updated: got %q", c.cfg.Realm)
	}
	if c.cfg.DefaultRole != "engineer" {
		t.Errorf("DefaultRole not updated: got %q", c.cfg.DefaultRole)
	}
}

func TestConfigUpdated_InvalidRoleMapping(t *testing.T) {
	c := newTestConnector(t, defaultTestCfg("http://localhost"), nil)
	err := c.ConfigUpdated(context.Background(), map[string]string{
		"role_mapping": "not-json",
	})
	if err == nil {
		t.Error("expected error for invalid role_mapping JSON")
	}
}

// ---------------------------------------------------------------------------
// Info and Schema
// ---------------------------------------------------------------------------

func TestInfo_OIDCMetadata(t *testing.T) {
	c := newTestConnector(t, defaultTestCfg("http://localhost"), nil)
	info := c.Info()
	if info.Metadata["identity_provider"] != "true" {
		t.Errorf("expected identity_provider=true, got %q", info.Metadata["identity_provider"])
	}
	if info.Metadata["identity_provider_type"] != "oidc" {
		t.Errorf("expected identity_provider_type=oidc, got %q", info.Metadata["identity_provider_type"])
	}
}

func TestAsIdentityProvider_ReturnsServer(t *testing.T) {
	c := newTestConnector(t, defaultTestCfg("http://localhost"), nil)
	if c.AsIdentityProvider() == nil {
		t.Error("AsIdentityProvider() must not return nil")
	}
}
