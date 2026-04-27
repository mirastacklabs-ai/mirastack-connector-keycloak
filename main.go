// Package main implements the mirastack-connector-keycloak process.
//
// It reads runtime configuration from environment variables, constructs
// the Keycloak OIDC connector, and calls mirastack.Serve() to start the
// gRPC server and register with the Mirastack Engine.
package main

import (
	"log"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	mirastack "github.com/mirastacklabs-ai/mirastack-connector-sdk-go"
)

func main() {
	// ── Logging ──────────────────────────────────────────────────────────────
	logLevel := zapcore.InfoLevel
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := logLevel.UnmarshalText([]byte(v)); err != nil {
			log.Printf("invalid LOG_LEVEL %q, defaulting to info", v)
		}
	}
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(logLevel)
	logger, err := zapCfg.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	// ── Config from environment ───────────────────────────────────────────────
	keycloakURL := mustEnv("KEYCLOAK_URL", logger)
	realm := mustEnv("KEYCLOAK_REALM", logger)
	clientID := mustEnv("KEYCLOAK_CLIENT_ID", logger)
	clientSecret := mustEnv("KEYCLOAK_CLIENT_SECRET", logger)

	roleMapping := envOrDefault("KEYCLOAK_ROLE_MAPPING", "")
	defaultRole := envOrDefault("KEYCLOAK_DEFAULT_ROLE", "operator")
	tlsSkipVerify := envBool("KEYCLOAK_TLS_SKIP_VERIFY", false)
	timeoutSec := envInt("KEYCLOAK_TIMEOUT_SECONDS", 10)
	providerName := envOrDefault("MIRASTACK_PROVIDER_NAME", "keycloak")
	pluginVersion := envOrDefault("MIRASTACK_PLUGIN_VERSION", "1.0.0")

	// Capture for startup log (these env vars are consumed by Serve() internally).
	engineAddr := envOrDefault("MIRASTACK_ENGINE_ADDR", "")
	grpcAddr := envOrDefault("MIRASTACK_PLUGIN_ADDR", "")

	cfg := KeycloakConfig{
		KeycloakURL:   keycloakURL,
		Realm:         realm,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RoleMapping:   roleMapping,
		DefaultRole:   defaultRole,
		TLSSkipVerify: tlsSkipVerify,
		TimeoutSec:    timeoutSec,
		ProviderName:  providerName,
	}

	connector, err := NewKeycloakConnector(cfg, pluginVersion, logger)
	if err != nil {
		logger.Fatal("failed to initialise Keycloak connector", zap.Error(err))
	}

	logger.Info("starting mirastack-connector-keycloak",
		zap.String("provider_name", providerName),
		zap.String("keycloak_url", keycloakURL),
		zap.String("realm", realm),
		zap.String("engine_addr", engineAddr),
		zap.String("plugin_addr", grpcAddr),
	)

	mirastack.Serve(connector)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustEnv(key string, logger *zap.Logger) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Fatal("required environment variable not set", zap.String("key", key))
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
