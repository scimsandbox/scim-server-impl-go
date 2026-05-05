# SCIM Sandbox - Server Impl Go

> [!WARNING]
> **Data Privacy / PII**: This application is built as a sandbox. It stores SCIM request and response payloads in the database without redaction for debugging purposes. Treat it as a local or development sandbox service, not a hardened production deployment.

This repository contains the standalone Go SCIM 2.0 service implementation
for the SCIM Sandbox project. It provides the server-side SCIM API,
workspace-scoped bearer-token auth, request and response logging, cleanup
jobs, discovery endpoints, and Prometheus metrics.

## What Is In This Repo

- `cmd/server/main.go` boots the service and delegates to `internal/app`.
- `internal/app` loads configuration, initializes the database, wires the
  routers, and manages the API and management listeners.
- `internal/handler` contains the SCIM `Users`, `Groups`, `Bulk`, discovery,
  and `/Me` handlers.
- `internal/repository`, `internal/service`, `internal/model`, and
  `internal/jdbc` contain the persistence layer, business logic, and shared
  data model.
- `internal/middleware` contains workspace extraction, bearer-token auth,
  request and response logging, and Prometheus metrics middleware.
- `internal/scim` contains SCIM discovery documents, schemas, error helpers,
  filter handling, and patch support.
- `internal/testsupport` contains helpers for container-backed PostgreSQL
  tests, including the migration bootstrap that builds the sibling
  `../scim-server-db` Flyway image.
- `config/app-conf.yaml` defines the default runtime settings and local
  development defaults.
- `config/app-secrets.yaml` is optional and can be used for local secret
  overrides.
- `Dockerfile` packages the service as a container image.

## Commands

The server binary supports three commands:

- `serve` starts the API and management listeners. This is the default.
- `healthcheck` calls `http://127.0.0.1:<management-port>/actuator/health`.
- `print-config` prints the merged runtime configuration with the database
  password masked.

Examples:

```bash
go run ./cmd/server
go run ./cmd/server healthcheck
go run ./cmd/server print-config
```

## API Shape

The SCIM API is workspace-scoped and uses UUID workspace IDs:

```text
/ws/{workspaceId}/scim/v2/**
```

An optional compatibility segment is also supported:

```text
/ws/{workspaceId}/scim/v2/{compat}/**
```

Requests use bearer-token authentication:

```text
Authorization: Bearer <workspace-token>
```

The service also exposes management endpoints on a separate listener:

- `/actuator/health`
- `/metrics`

These management endpoints are not authenticated.

## Running the Service

Prerequisites:

- Go 1.25
- PostgreSQL if you want to point the app at a local database
- Docker if you want to build the image or run container-backed tests

The repository ships with local-development defaults in `config/app-conf.yaml`:

- `jdbc:postgresql://localhost:5432/scimplayground`
- username `scim_playground`
- password `scim_playground`

If your local database differs, override the defaults before starting the
service:

```bash
export GO_DATASOURCE_URL=jdbc:postgresql://localhost:5432/scimplayground
export GO_DATASOURCE_USERNAME=scim_playground
export GO_DATASOURCE_PASSWORD=scim_playground
```

Start the service from the repository root:

```bash
go run ./cmd/server
```

The application listens on port `8080` by default. The management listener
uses port `9090` by default.

## Example Calls

Discovery:

```bash
export WORKSPACE_ID=<workspace-uuid>
export TOKEN=<workspace-token>

curl \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/scim+json" \
  http://localhost:8080/ws/${WORKSPACE_ID}/scim/v2/ServiceProviderConfig
```

Create a user:

```bash
curl \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/scim+json" \
  -H "Accept: application/scim+json" \
  http://localhost:8080/ws/${WORKSPACE_ID}/scim/v2/Users \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com",
    "name": {
      "givenName": "Alice",
      "familyName": "Example"
    },
    "active": true
  }'
```

Management health:

```bash
curl http://localhost:9090/actuator/health
```

Prometheus metrics:

```bash
curl http://localhost:9090/metrics
```

The Go service exposes custom SCIM metrics with the `scim_go_` prefix:

- `scim_go_operation_requests_total`
- `scim_go_operation_duration_seconds`

Both metrics use the same label set as the Spring implementation, with the Go
metric-name prefix kept as `scim_go_`: `operation`, `resource`, `action`,
`workspace_id`, `user_email`, `http_status`, `outcome`, `authentication`, and
`throttled`.

Because `/metrics` uses Prometheus' default registry, it also exposes Go
runtime and process metrics such as:

- `go_goroutines`
- `go_memstats_alloc_bytes`
- `go_gc_duration_seconds`
- `process_cpu_seconds_total`
- `process_resident_memory_bytes`
- `process_start_time_seconds`

## Configuration

The default application settings live in `config/app-conf.yaml`. At startup,
the service loads:

- `config/app-conf.yaml`
- `config/app-secrets.yaml` if it exists

Set `GO_CONFIG_DIR` to point the service at a different configuration
directory.

Useful environment overrides:

- `GO_SERVER_PORT`
- `GO_MANAGEMENT_PORT`
- `GO_DATASOURCE_URL`
- `GO_DATASOURCE_USERNAME`
- `GO_DATASOURCE_PASSWORD`
- `GO_DATASOURCE_MAX_CONNS`
- `GO_DATASOURCE_MIN_CONNS`
- `GO_CLEANUP_ENABLED`
- `GO_CLEANUP_INTERVAL`
- `GO_CLEANUP_STALE_AFTER`
- `GO_LOGGING_LEVEL`
- `GO_MESSAGES_LANGUAGE`

The storage URL should be provided in JDBC form, for example
`jdbc:postgresql://localhost:5432/scimplayground`. The service converts that
URL into a pgx-compatible DSN and adds `sslmode=disable` when it is not
already present.

For compatibility with existing local setups, the `serve` command also honors
these environment variables when they are set:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `SERVER_PORT`

Workspace cleanup is enabled by default. The shipped defaults run cleanup every
`2h` and remove stale workspaces older than `2160h` (90 days).

### Token Expiration

Workspace bearer tokens carry an optional `expires_at` timestamp. The auth
middleware rejects revoked tokens, tokens that belong to a different
workspace, and tokens whose `expires_at` is in the past with `401
Unauthorized`. Tokens with a `NULL` expiry continue to be accepted until they
are revoked.

### Payload Limits

The Bulk endpoint enforces the SCIM-advertised `maxPayloadSize` limit of
`1048576` bytes (1 MB). Requests larger than that are rejected before bulk
processing starts.

## Testing

Run the default package test suite from the repository root:

```bash
go test ./...
```

Container-backed validation runs with the normal test set. Common examples:

```bash
go test ./internal/handler -run TestCreateAndGetUser -count=1
go test ./internal/integration -run TestGroupMembershipTransaction -count=1
go test ./internal/integration -run TestGroupMembershipTransactionDockertest -count=1
go test ./internal/integration -run TestGroupMembershipTransactionDockerCLI -count=1
```

The Docker-backed integration helpers require Docker. They also build and run the
sibling `../scim-server-db` image automatically so Flyway migrations are
applied before the tests execute.

## Versioning

Go module and release consumers should rely on semantic Git tags in the form
`vX.Y.Z`. This repository keeps the current released version in the root
`VERSION` file so automation has a single tracked source of truth.

When you run the release workflow from `main`, choose the semantic bump type:
`patch`, `minor`, or `major`.

The workflow reads `VERSION`, computes the next version, writes the new value
back to `VERSION`, commits that change, creates the matching Git tag, and
publishes the release artifacts.
