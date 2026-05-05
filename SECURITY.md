# Security Policy

## Supported Versions

This repository supports the latest code on the `main` branch and the
latest image or binary built from that branch.

Because this repository was split from a larger SCIM Sandbox codebase, it
does not assume long-lived maintenance branches. Fixes are expected to
land on `main` first.

## Reporting a Vulnerability

Do not open public GitHub issues for security vulnerabilities.

Use GitHub Security Advisories for private reporting:

1. Open the repository Security tab.
2. Select Advisories.
3. Create a new draft security advisory.
4. Include the affected files or endpoints, reproduction steps, impact,
   and any suggested mitigation.

If GitHub private reporting is unavailable, use the maintainer contact
options on the GitHub profile.

## Scope of Security Review

Security-sensitive areas in this repository include:

- bearer token generation, hashing, revocation, and expiry handling
- bearer-token authentication and workspace resolution from SCIM routes
- request and response logging for SCIM traffic
- SCIM filter parsing, PATCH handling, bulk processing, and error mapping
- `/Me`, discovery, and schema endpoints
- workspace cleanup scheduling and retention
- database persistence and the runtime configuration used to reach it
- configuration loading, environment overrides, and datasource DSN translation
- Docker and release workflow changes that affect how artifacts are built or distributed

## Operational Guidance

> [!WARNING]
> **Data Privacy / PII**: This application is built as a sandbox. It stores all SCIM request and response payloads in the database without redaction for debugging purposes. Review this behavior before handling sensitive or regulated data.

If you deploy this service outside a local sandbox, apply these controls
first:

1. Use HTTPS end to end.
2. Replace datasource credentials with environment-specific secrets.
3. Treat workspace bearer tokens as secrets and rotate them when environments change.
4. Keep the SCIM API and management endpoints behind a trusted proxy or otherwise restrict their exposure.
5. Use separate databases and runtime configuration per environment.
6. Verify the request and response logging posture and the workspace cleanup retention window before enabling the service in production-like environments.

## Secrets Handling

- Do not commit workspace bearer tokens.
- Do not commit datasource passwords or connection strings.
- Do not commit copied values from `config/app-secrets.yaml`.
- Do not reuse local sandbox values in shared or production-like environments.
- Keep publishing credentials such as GitHub or Docker tokens in repository secrets, not in workflow files or shell history.

## Current Mitigations

The service currently includes these baseline controls:

- SHA-256 hashing for workspace bearer tokens before persistence
- token revocation and optional expiry support
- workspace ownership enforcement in the auth middleware
- invalid workspace UUIDs returning SCIM `404` responses
- SCIM-compliant error responses for malformed and unsupported requests
- a SCIM-advertised 1MB `maxPayloadSize` limit on Bulk requests
- configuration loading that rejects YAML anchors and merge keys
- scheduled cleanup of stale workspaces

## Security Testing Expectations

When changing authentication, authorization, request handling, logging,
cleanup, configuration loading, or persistence, validate the relevant
tests and run `go test ./...`.

The most relevant focused tests include:

- `TestHashToken`
- `TestGenerateSecureToken`
- `TestUserEndpointsRejectCrossWorkspaceToken`
- `TestGroupEndpointsRejectCrossWorkspaceToken`
- `TestCreateAndGetUser`
- `TestCreateAndGetGroup`
- `TestBulkResolvesBulkIdsAcrossOperations`
- `TestBulkStopsAfterConfiguredErrorThreshold`
- `TestParseUserFilter_SupportedAttributes`
- `TestApplyPatchOperations_FilteredReplace`
- `TestWorkspaceCleanupService_cleanup_LogsErrorWhenRepoFails`
- `TestGroupMembershipTransaction` and its tagged Docker variants