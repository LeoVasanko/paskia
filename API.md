# PassKey Auth API Documentation

This document lists the HTTP and WebSocket endpoints exposed by the PassKey Auth
service and how they behave depending on whether a dedicated authentication host
(`--auth-host` / environment `PASSKEY_AUTH_HOST`) is configured.

## Base Paths & Host Modes

Two deployment modes:

1. Multi‑host (default – no `--auth-host` provided)
   - All endpoints are reachable on any host under the `/auth/` prefix.
   - A convenience root (`/`) also serves the main app.

2. Dedicated auth host (`--auth-host auth.example.com`)
   - The specified auth host serves the UI at the root (`/`, `/admin/`, reset tokens, etc.).
   - Other (non‑auth) hosts show a lightweight account summary at `/` or `/auth/`, while other UI routes still redirect to the auth host.
   - Restricted endpoints on non‑auth hosts return `404` instead of redirecting.

### Path Mapping When Auth Host Enabled

| Purpose | On Auth Host | On Other Hosts (incoming) | Action |
|---------|--------------|---------------------------|--------|
| Main UI | `/` | `/auth/` or `/` | Serve account summary SPA (no redirect) |
| Admin UI root | `/admin/` | `/auth/admin/` or `/admin/` | Redirect -> auth host `/admin/` (strip `/auth`) |
| Reset / device addition token | `/{token}` | `/auth/{token}` | Redirect -> auth host `/{token}` (strip `/auth`) |
| Static assets | `/auth/assets/*` | `/auth/assets/*` | Served directly (no redirect) |
| Unrestricted API | `/auth/api/...` | `/auth/api/...` | Served directly |
| Restricted API (admin,user,ws namespaces) | `/auth/api/{admin|user|ws}*` | same path | 404 on non‑auth hosts |
| WebSocket (register/auth) | `/auth/ws/*` | `/auth/ws/*` | 404 on non‑auth hosts |

Notes:
- “Strip `/auth`” means only when the path starts with that exact segment.
- A reset token is a single path segment validated by server logic; malformed tokens 404.
- Method and body are preserved for UI redirects (307 Temporary Redirect).

## HTTP UI Endpoints

| Method | Path (multi‑host) | Path (auth host) | Description |
|--------|-------------------|------------------|-------------|
| GET | `/auth/` | `/` | Main authentication SPA (non-auth hosts show an account summary view) |
| GET | `/auth/admin/` | `/admin/` | Admin SPA root |
| GET | `/auth/{reset_token}` | `/{reset_token}` | Reset / device addition SPA (token validated) |

## Core API (Unrestricted – available on all hosts)

Always under `/auth/api/` (even on auth host):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/restricted` | Authentication UI for iframe embedding (supports `?mode=login` or `?mode=reauth`) |
|--------|------|-------------|
| POST | `/auth/api/validate` | Validate & (conditionally) renew session |
| GET | `/auth/api/forward` | Auth proxy endpoint for reverse proxies (204 or 4xx) |
| POST | `/auth/api/set-session` | Set cookie from Bearer token |
| POST | `/auth/api/logout` | Logout current session |
| POST | `/auth/api/user-info` | Authenticated user + context info (also handles reset tokens) |
| POST | `/auth/api/create-link` | Create a device addition link (reset token) |
| DELETE | `/auth/api/credential/{uuid}` | Delete user credential |
| DELETE | `/auth/api/session/{session_id}` | Terminate a specific session |
| POST | `/auth/api/user/logout-all` | Terminate all sessions for the user |
| PUT | `/auth/api/user/display-name` | Update display name |

## Restricted API Namespaces

When `--auth-host` is set, requests to these paths on non‑auth hosts return 404:

| Namespace | Examples |
|-----------|----------|
| `/auth/api/admin` | `/auth/api/admin/orgs`, `/auth/api/admin/orgs/{uuid}` ... |
| `/auth/api/user` | Segment prefix – includes `/auth/api/user/...` endpoints (logout-all, display-name, session, credential) |
| `/auth/api/ws` | (Reserved / future) |

## WebSockets (Passkey)

| Path | Description | Host Mode Behavior |
|------|-------------|--------------------|
| `/auth/ws/register` | Register new credential (new or existing user) | 404 on non‑auth hosts when auth host configured |
| `/auth/ws/authenticate` | Authenticate user & issue session | 404 on non‑auth hosts when auth host configured |

## Redirection & Status Codes

| Scenario | Response |
|----------|----------|
| UI path on non‑auth host (auth host configured) | 307 redirect to auth host; `/auth` prefix stripped |
| Reset token UI path on non‑auth host | 307 redirect (token preserved) |
| Restricted API on non‑auth host | 404 |
| Unrestricted API on any host | Normal response |
| No auth host configured | All hosts behave like multi-host mode (no redirects; everything accessible) |

## Headers for /auth/api/forward
See `Headers.md` for details of headers returned on success (204).

## Notes for Integrators
1. Always use absolute `/auth/api/...` paths for programmatic requests (they do not move when an auth host is introduced).
2. Bookmark / deep links to UI should resolve correctly after redirection if users access via a non-auth application host.
3. Treat 404 from restricted namespaces on non-auth hosts as a signal to direct users to the central auth site.

## Environment & CLI Summary
| Option | Effect |
|--------|--------|
| `--auth-host` / `PASSKEY_AUTH_HOST` | Enables dedicated host mode, root-mounts UI there, restricts certain namespaces elsewhere |

---
This document reflects current behavior of the middleware-based host routing logic.
