# Paskia HTTP + WebSocket surface

This document is a factual map of the URLs Paskia exposes.

Two important distinctions:

1. **User‑navigable endpoints**: URLs a human types/scans into a browser (address bar / QR).
2. **API endpoints**: URLs the app uses programmatically (frontend or backend).

Within **API endpoints**, the most important group comes first:

- **`/auth/api/*`**: stable API surface that is reachable on any host (including non‑auth hosts).
- **Auth‑host‑only namespaces**: only reachable on the dedicated auth host when `--auth-host` is configured.

## Host modes (what changes when `--auth-host` is set)

Paskia can run in either mode:

- **Multi‑host** (default, no `--auth-host`): all routes below are served on the current host.
- **Dedicated auth host** (`--auth-host auth.example.com`):
   - Certain UI routes are redirected to the auth host.
   - Certain sensitive API and WebSocket namespaces are **not served** on non‑auth hosts (they return `404`).

Rules are enforced by middleware in `paskia/fastapi/auth_host.py`.

### Summary table (dedicated auth host mode)

| Category | Example path | On non‑auth hosts | On auth host |
|---|---|---:|---:|
| User‑navigable UI (root/admin/token) | `/admin/`, `/{token}` | 307 redirect (strip `/auth` when present) | served locally |
| Static assets | `/auth/assets/*` | served locally | served locally |
| App API (stable surface) | `/auth/api/validate` | served locally | served locally |
| Auth‑host‑only API | `/auth/api/admin/*`, `/auth/api/user/*` | **404** | served locally |
| Auth‑host‑only WebSockets | `/auth/ws/*` | **404** | served locally |

Notes:
- “Strip `/auth`” applies only to UI redirects (e.g. `/auth/admin/` → `/admin/` on the auth host).
- Redirects use HTTP `307` so method/body are preserved.

---

## API endpoints (programmatic)

### 1) Stable app API (reachable on any host): `/auth/api/*`

These endpoints are intended for programmatic use by:

- the browser frontend, and/or
- backend services (reverse proxies, gateways) that need to validate sessions/permissions.

They remain under the `/auth/api/` prefix even when the auth UI moves to `/` on the auth host.

#### Session validation & permission checks

`POST /auth/api/validate`
- Purpose: validate the current session cookie and optionally renew it (sliding expiry).
- Query: `perm=<id>` (repeatable) — all listed permission IDs are required.
- Response: JSON with `valid`, `user_uuid`, `renewed`.

`GET /auth/api/forward`
- Purpose: “forward auth” endpoint for reverse proxies (Caddy/Nginx). Returns `204` with `Remote-*` headers on success.
- Query:
   - `perm=<id>` (repeatable): required permissions.
   - `max_age=<duration>`: require recent authentication (e.g. `5m`, `1h`, `30s`).
- Response:
   - success: `204 No Content` + headers
   - failure: `4xx` with either JSON or HTML depending on `Accept`.

See [Headers.md](Headers.md) for the `Remote-*` header contract.

#### Client configuration

`GET /auth/api/settings`
- Purpose: fetch runtime configuration for the frontend (RP ID/name, base paths, auth-host mode).

#### Reset / link flows

`GET /auth/api/token-info?token=<token>`
- Purpose: validate a reset token and return minimal metadata for the reset UI.
- Notes: invalid or expired tokens return `404`.

`POST /auth/api/user-info`
- Purpose: fetch user info.
- Modes:
   - session mode: uses auth cookie
   - reset mode: pass `reset=<token>` (for reset/device-add flows)

#### Session cookie management

`POST /auth/api/logout`
- Purpose: delete the current session (best-effort) and clear the auth cookie.

`POST /auth/api/set-session`
- Purpose: exchange a Bearer session token for an auth cookie.
- Auth: `Authorization: Bearer <session_token>`.

---

### 2) Auth‑host‑only API (not reachable on other hosts): `/auth/api/user/*`

These endpoints are still “app API”, but are intentionally blocked on non‑auth hosts when `--auth-host` is configured.

Base prefix: `/auth/api/user`

`PUT /auth/api/user/display-name`
- Body: JSON `{ "display_name": "…" }`

`POST /auth/api/user/logout-all`
- Purpose: terminate all sessions for the user; clears current cookie.

`DELETE /auth/api/user/session/{session_id}`
- Purpose: terminate a specific session for the current user.

`DELETE /auth/api/user/credential/{uuid}`
- Purpose: delete a credential (requires recent authentication).

`POST /auth/api/user/create-link`
- Purpose: create a device addition link (reset token) for the current user (requires recent authentication).

---

### 3) Auth‑host‑only admin API (not reachable on other hosts): `/auth/api/admin/*`

Base prefix: `/auth/api/admin`

UI root (served by the admin sub-app):
- `GET /auth/api/admin/` (serves the admin SPA HTML)

Organizations:
- `GET /auth/api/admin/orgs`
- `POST /auth/api/admin/orgs`
- `PUT /auth/api/admin/orgs/{org_uuid}`
- `DELETE /auth/api/admin/orgs/{org_uuid}`
- `POST /auth/api/admin/orgs/{org_uuid}/permission`
- `DELETE /auth/api/admin/orgs/{org_uuid}/permission`

Roles:
- `POST /auth/api/admin/orgs/{org_uuid}/roles`
- `PUT /auth/api/admin/orgs/{org_uuid}/roles/{role_uuid}`
- `DELETE /auth/api/admin/orgs/{org_uuid}/roles/{role_uuid}`

Users:
- `POST /auth/api/admin/orgs/{org_uuid}/users`
- `PUT /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}/role`
- `POST /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}/create-link`
- `GET /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}`
- `PUT /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}/display-name`
- `DELETE /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}/credentials/{credential_uuid}`
- `DELETE /auth/api/admin/orgs/{org_uuid}/users/{user_uuid}/sessions/{session_id}`

Permissions (global):
- `GET /auth/api/admin/permissions`
- `POST /auth/api/admin/permissions`
- `PUT /auth/api/admin/permission`
- `POST /auth/api/admin/permission/rename`
- `DELETE /auth/api/admin/permission`

---

## WebSocket endpoints

All WebSocket endpoints are mounted under `/auth/ws/` and are **auth‑host‑only** when `--auth-host` is configured.

### Passkey WebAuthn

`WS /auth/ws/authenticate`
- Purpose: authenticate using a passkey.
- Response includes `session_token` (use `POST /auth/api/set-session` to set the cookie).

`WS /auth/ws/register`
- Purpose: register a new credential.
- Query:
   - `reset=<token>` (optional): allow registration via reset link
   - `name=<display name>` (optional)

### Remote authentication (cross-device)

Mounted under `/auth/ws/remote-auth`:

`WS /auth/ws/remote-auth/request`
- Purpose: create a pairing code and wait for approval.

`WS /auth/ws/remote-auth/permit`
- Purpose: approve/deny a pairing code from another device.

---

## User‑navigable endpoints (browser)

These are the URLs a user should be able to open directly.

`GET /` and `GET /auth/`
- Serves the user profile app.

`GET /admin/` (and legacy `/auth/admin/`)
- Admin UI (may redirect to the auth host in dedicated auth-host mode).

`GET /{token}` (and legacy `/auth/{token}`)
- Reset / device addition UI for a single path segment token.
- Token format is validated; malformed tokens return `404`.

`GET /auth/restricted/`
- Special HTML UI used for iframe-based authentication flows (primarily via `/auth/api/forward`).
