# llm-permission-proxy

Rust + SQLite proxy for Cloudflare operations with explicit async approval flow.

## Key behavior

- All operations go through policy evaluation at proxy level.
- Agents do not hold Cloudflare credentials.
- `POST /v1/tasks/{task_id}/apply` is multi-stage:
  - executes immediately when pre-approved
  - returns `202` with `requires_approval` when escalation is needed
- Approvals are completed out-of-band (Discord link + WebAuthn endpoints).
- Idempotency keys prevent duplicate execution.
- Callback events notify orchestrators (`approval.*`, `apply.*`).
- Admin endpoints can manage agent permissions and approver passkey credential IDs.

## Environment

- `BIND_ADDR` (default: `127.0.0.1:8080`)
- `DATABASE_URL` (default: `sqlite://data/proxy.db`)
- `JWT_SECRET` (default: `dev-change-me`)
- `JWT_ISSUER` (default: `llm-permission-proxy`)
- `JWT_AUDIENCE` (default: `llm-proxy-api`)
- `BASE_URL` (default: `http://localhost:8080`)
- `WEBAUTHN_RP_ID` (default: `localhost`)
- `WEBAUTHN_ORIGIN` (default: `http://localhost:8080`)
- `CLOUDFLARE_API_TOKEN` (optional)
- `CLOUDFLARE_API_BASE` (default: `https://api.cloudflare.com/client/v4`)

## Notes

- WebAuthn verify endpoint currently validates challenge/origin/credential binding and assertion presence.
- For production passkey assurance, add full cryptographic signature verification against stored credential public keys.
