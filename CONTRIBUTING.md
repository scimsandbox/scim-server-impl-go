# Contributing

Thanks for contributing to scim-server-impl-go.

This repository contains the standalone Go SCIM server implementation for
the SCIM Sandbox project. Keep changes focused on API behavior,
persistence, security, release workflow changes, or documentation that
matches the live repository structure.

## Ground Rules

- Keep each change narrow and intentional.
- Do not mix unrelated refactors into API, persistence, workflow, or
  documentation changes.
- Do not commit bearer tokens, datasource credentials, copied secret
  overrides, or generated logs.
- Prefer the existing `cmd/server`, `internal/app`, `internal/handler`,
  `internal/middleware`, `internal/service`, `internal/repository`, and
  `internal/scim` layout over new abstractions unless there is a clear
  gain.
- Update tests and docs when API behavior, configuration keys, runtime
  defaults, or release flow changes.

## Before You Start

1. Check for existing issues or pull requests that already cover the same work.
2. Read [README.md](./README.md) and [SECURITY.md](./SECURITY.md) before changing runtime or security behavior.
3. If the change touches request or response shape, update handlers, SCIM mapping, services, and tests together.
4. If the change touches Docker-backed integration-test behavior, keep the Dockerfile, test helpers, scripts, and docs consistent.

## Working Conventions

- Keep the application entrypoint under `cmd/server` and keep internal packages under `internal/**`.
- Keep the current released version in the root `VERSION` file; the release workflow bumps it based on a `patch`/`minor`/`major` input and publishes matching `vX.Y.Z` tags.
- Keep SCIM routes workspace-scoped under `/ws/{workspaceId}/scim/v2/**`.
- Preserve the optional compatibility segment under `/ws/{workspaceId}/scim/v2/{compat}/**` when changing routing behavior.
- `workspaceId` route parameters remain UUID-based.
- `/Me` remains a `501 Not Implemented` endpoint unless the repository explicitly gains subject-to-resource mapping.
- Request logging remains workspace-scoped and stores SCIM request and response bodies unless a deliberate security change says otherwise.
- Keep the API and management listeners separately configurable when changing startup or runtime wiring.
- Prefer the standard library and the existing package boundaries over new framework-style layers unless there is a clear gain.

## Validation

Validate changes before opening a PR.

Common checks:

- run `gofmt` on changed Go files
- run `go test ./...`
- if you changed handler or persistence flows, run a focused test such as `go test ./internal/handler -run TestCreateAndGetUser -count=1`
- if you changed cross-package database behavior, run a focused integration test such as `go test ./internal/integration -run TestGroupMembershipTransaction -count=1`
- if Docker-backed tests use a different migration image or local setup, make sure the sibling `../scim-server-db` image can still be built by the test helpers

## Pull Request Checklist

- explains the API or persistence change and why it is needed
- updates docs and configuration when runtime behavior or environment keys change
- keeps secrets and machine-specific values out of the diff
- avoids unrelated cleanup
- passes the relevant validation steps

## Reporting Bugs

When reporting a server issue, include:

- the affected endpoint or component
- the request path, method, and payload
- the expected and actual SCIM response
- the relevant environment or configuration details with secrets removed
- the test name or reproduction steps, if known

## Security Issues

Do not report vulnerabilities through public issues. Follow
[SECURITY.md](./SECURITY.md) instead.