# llm-permission-proxy

Rust + SQLite proxy for Cloudflare operations with explicit approval flow and strict privilege boundaries.

## Security model

- Task capability tokens are **task-scoped only**.
- Service-admin operations (`/v1/tasks` creation, agent permission management, approver credential management) require a **bootstrap JWT**.
- Protected routes require signed mTLS identity headers:
  - `x-client-subject`
  - `x-client-subject-ts`
  - `x-client-subject-sig`
- Header signature format:
  - `hex(HMAC_SHA256(MTLS_BINDING_SHARED_SECRET, "{subject}\n{unix_ts}"))`
  - timestamp skew must be within `±60s`.

## Key behavior

- `POST /v1/tasks/{task_id}/apply` is multi-stage:
  - executes immediately when pre-approved
  - returns `202` with `requires_approval` when escalation is needed
- Approval links and resume tokens are signed opaque tokens (not plaintext DB columns).
- Idempotency keys prevent duplicate execution.
- Callback events notify orchestrators (`approval.*`, `apply.*`).
- Callback registration and delivery are restricted to HTTPS + explicit host allowlist.

## Environment

### Core

- `BIND_ADDR` (default: `127.0.0.1:8080`)
- `DATABASE_URL` (default: `sqlite://data/proxy.db`)
- `BASE_URL` (default: `http://localhost:8080`)

### Capability token auth (task-scoped)

- `JWT_SECRET` (**required unless `ALLOW_INSECURE_DEFAULTS=true`**)
- `JWT_ISSUER` (default: `llm-permission-proxy`)
- `JWT_AUDIENCE` (default: `llm-proxy-api`)

### Bootstrap auth (service-admin routes)

- `BOOTSTRAP_JWT_SECRET` (**required unless `ALLOW_INSECURE_DEFAULTS=true`**)
- `BOOTSTRAP_JWT_ISSUER` (default: `llm-permission-proxy-bootstrap`)
- `BOOTSTRAP_JWT_AUDIENCE` (default: `llm-proxy-bootstrap`)

### mTLS header binding and approval token signing

- `MTLS_BINDING_SHARED_SECRET` (**required unless `ALLOW_INSECURE_DEFAULTS=true`**)
- `APPROVAL_LINK_SECRET` (**required unless `ALLOW_INSECURE_DEFAULTS=true`**)
- `RESUME_TOKEN_SECRET` (**required unless `ALLOW_INSECURE_DEFAULTS=true`**)

### Callback hardening

- `CALLBACK_ALLOWED_HOSTS` (comma-separated host allowlist, default: `localhost`)

### Approval / callback tuning

- `CALLBACK_MAX_RETRIES` (default: `5`)
- `CALLBACK_BATCH_SIZE` (default: `50`)
- `CALLBACK_WORKER_INTERVAL_SECS` (default: `2`)
- `APPROVAL_TTL_SECONDS` (default: `600`)
- `APPROVAL_NONCE_TTL_SECONDS` (default: `90`)

### WebAuthn

- `WEBAUTHN_RP_ID` (default: `localhost`)
- `WEBAUTHN_ORIGIN` (default: `http://localhost:8080`)

### Cloudflare

- `CLOUDFLARE_API_TOKEN` (optional; if missing, operations are simulated)
- `CLOUDFLARE_API_BASE` (default: `https://api.cloudflare.com/client/v4`)

### Development override

- `ALLOW_INSECURE_DEFAULTS` (default: `false`)
  - when `false`, startup fails if required security secrets are missing
  - when `true`, development defaults are accepted

## Breaking schema reset note

This repository is MVP-only and uses inline bootstrap DDL (no migration system).  
Security hardening changed bootstrap schema:

- `capability_tokens` includes `claims_hash`
- `approvals` no longer stores plaintext/hash nonce or resume token columns

Existing SQLite files should be replaced/reinitialized for this cutover.

## Smoke test (no migrations)

```bash
./scripts/bootstrap_sqlite_smoke_test.sh
```

What it verifies:

- Server starts and `/v1/readyz` responds.
- `approver_credentials` verifier columns exist.
- `capability_tokens.claims_hash` exists.
- legacy approval plaintext/hash token columns are absent.
- no `_sqlx_migrations` table exists.

## Automated checks

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
./scripts/bootstrap_sqlite_smoke_test.sh
```
