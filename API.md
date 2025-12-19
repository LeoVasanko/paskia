# Paskia endpoints (integration-focused)

Use these tables when integrating Paskia authentication into your app.

## Behavior when `--auth-host` is enabled

| Path / type | What happens on non-auth hosts |
|---|---|
| `/auth/api/*` | Served normally |
| `/auth/api/user/*` | `404` |
| `/auth/api/admin/*` | `404` |
| `/auth/ws/*` | `404` |
| Browser UI URLs like `/admin/`, `/{token}`, and legacy `/auth/...` | `307` redirect to the auth host (UI redirects strip the `/auth` prefix) |

## Browser URLs (user-navigable)

| Method | Path | What it is for | Notes |
|---:|---|---|---|
| GET | `/` | User profile UI | On app hosts you can also use `/auth/` |
| GET | `/auth/` | User profile UI (legacy entry) | Redirects to `/` on the auth host |
| GET | `/admin/` | Admin UI | Legacy entry: `/auth/admin/` |
| GET | `/{token}` | Reset / registration / device-add UI | Legacy entry: `/auth/{token}`; invalid tokens return `404` |
| GET | `/auth/restricted/` | HTML UI used by the auth-forward flow | Typically shown via `/auth/api/forward` on failures |

## App HTTP API (reachable on any host): `/auth/api/*`

| Method | Path | Used for | Inputs / outputs (high level) |
|---:|---|---|---|
| POST | `/auth/api/validate` | Validate session cookie; optionally renew | Query: `perm` (repeatable). JSON response includes `valid`, `user_uuid`, `renewed` |
| GET | `/auth/api/forward` | Reverse-proxy auth check (Caddy/Nginx) | Query: `perm` (repeatable), `max_age`. Success: `204` with `Remote-*` headers; failures: `4xx` JSON or HTML depending on `Accept` |
| POST | `/auth/api/set-session` | Turn a Bearer session token into a cookie | Header: `Authorization: Bearer <session_token>`; sets cookie |
| POST | `/auth/api/logout` | Clear cookie and delete session (best-effort) | Returns JSON message |
| GET | `/auth/api/settings` | Fetch runtime settings for clients | Returns RP info + base paths + auth-host info |
| GET | `/auth/api/token-info` | Validate reset token and fetch minimal metadata | Query: `token=<token>`; invalid/expired returns `404` |
| POST | `/auth/api/user-info` | Fetch user info for UI | Either session cookie, or `reset=<token>` for reset flows |

See [Headers.md](Headers.md) for the `Remote-*` header contract used by `/auth/api/forward`.

## Auth-host-only HTTP APIs (usually not needed for app integration)

| Audience | Method | Path | Used for |
|---:|---:|---|---|
| User | PUT | `/auth/api/user/display-name` | Update the user’s display name |
| User | POST | `/auth/api/user/logout-all` | Terminate all user sessions and clear cookie |
| User | DELETE | `/auth/api/user/session/{session_id}` | Terminate one session |
| User | DELETE | `/auth/api/user/credential/{uuid}` | Delete a credential (requires recent auth) |
| User | POST | `/auth/api/user/create-link` | Create a device-add link (requires recent auth) |
| Admin | GET | `/auth/api/admin/` | Admin UI entry (serves the admin SPA HTML) |
| Admin | * | `/auth/api/admin/*` | Admin management API (orgs, roles, users, permissions) |

## WebSockets (auth-host-only when `--auth-host` is enabled)

| Path | Used for | Notes |
|---|---|---|
| `WS /auth/ws/authenticate` | Passkey authentication | Returns a `session_token` that can be exchanged via `POST /auth/api/set-session` |
| `WS /auth/ws/register` | Register a new credential | Optional query: `reset=<token>`, `name=<display name>` |
| `WS /auth/ws/remote-auth/request` | Start a cross-device login/registration request | Returns a pairing code |
| `WS /auth/ws/remote-auth/permit` | Approve/deny a pairing code | Used from an already-authenticated device |
