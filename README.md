# mirastack-connector-keycloak

MIRASTACK auth connector for **Keycloak** (OIDC — Resource Owner Password Credentials flow).

This is an **OSS** plugin distributed under the **AGPL v3** license.

---

## Authentication Flow

1. POST `{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token` with `grant_type=password`.
2. Decode the returned JWT access token: extract `sub`, `email`, `preferred_username`, `name`, `realm_access.roles`.
3. Map Keycloak realm roles to Mirastack roles via `KEYCLOAK_ROLE_MAPPING`.
4. Return the populated identity to the engine for JIT user provisioning.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_URL` | ✅ | — | Base URL of the Keycloak server, e.g. `https://keycloak.corp.local:8443` |
| `KEYCLOAK_REALM` | ✅ | — | Keycloak realm name, e.g. `mirastack` |
| `KEYCLOAK_CLIENT_ID` | ✅ | — | OIDC client identifier registered in the realm |
| `KEYCLOAK_CLIENT_SECRET` | ✅ | — | OIDC client secret |
| `KEYCLOAK_ROLE_MAPPING` | ❌ | `{}` | JSON map of Keycloak realm role → Mirastack role. Example: `{"keycloak-admin":"admin","platform-engineer":"engineer"}` |
| `KEYCLOAK_DEFAULT_ROLE` | ❌ | `operator` | Role assigned when no realm role mapping resolves |
| `KEYCLOAK_TLS_SKIP_VERIFY` | ❌ | `false` | Disable TLS certificate verification (dev/self-signed only) |
| `KEYCLOAK_TIMEOUT_SECONDS` | ❌ | `10` | Per-request HTTP timeout |
| `MIRASTACK_PROVIDER_NAME` | ❌ | `keycloak` | Canonical provider name reported to the engine |
| `MIRASTACK_ENGINE_ADDR` | ✅ | — | Engine gRPC address, e.g. `mirastack-engine:9090` |
| `MIRASTACK_PLUGIN_ADDR` | ❌ | `:0` | Listen address for the connector gRPC server |
| `MIRASTACK_PLUGIN_ADVERTISE_ADDR` | ❌ | — | Advertised address sent to engine (set in container deployments) |
| `MIRASTACK_PLUGIN_VERSION` | ❌ | `1.0.0` | Plugin version string |

---

## Role Mapping

Keycloak realm roles are mapped to Mirastack roles in priority order:

1. **Explicit `KEYCLOAK_ROLE_MAPPING`** — overrides well-known names.
2. **Well-known names** — `admin`, `mirastack-admin`, `administrator` → `admin`; `engineer`, `mirastack-engineer` → `engineer`; `operator`, `mirastack-operator` → `operator`.
3. **`KEYCLOAK_DEFAULT_ROLE`** — applied when no mapping resolves.

When a user has multiple roles, the highest-privilege role wins.

---

## Docker Compose Snippet

```yaml
connector-keycloak:
  image: mirastack-connector-keycloak
  build:
    context: ../../..
    dockerfile: connectors/AAAA/oss/mirastack-connector-keycloak/Dockerfile
  ports:
    - "50081:50051"
  environment:
    MIRASTACK_PLUGIN_ADDR: ":50051"
    MIRASTACK_PLUGIN_ADVERTISE_ADDR: "connector-keycloak:50051"
    MIRASTACK_ENGINE_ADDR: "mirastack-engine:9090"
    KEYCLOAK_URL: "http://keycloak:8080"
    KEYCLOAK_REALM: "mirastack"
    KEYCLOAK_CLIENT_ID: "mira-cli"
    KEYCLOAK_CLIENT_SECRET: "${KEYCLOAK_CLIENT_SECRET}"
    KEYCLOAK_DEFAULT_ROLE: "operator"
  depends_on:
    mirastack-engine:
      condition: service_started
```
