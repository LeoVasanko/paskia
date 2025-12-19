# Paskia API

Use these tables when integrating Paskia authentication into your app.

### Browser URLs (user-navigable)

| Method | Path | What it is for | Notes |
|---:|---|---|---|
| GET | `/` | User profile UI | On app hosts you can also use `/auth/` |
| GET | `/auth/` | User profile UI (legacy entry) | Alternative entry point for `/` |
| GET | `/admin/` | Admin UI | Legacy entry: `/auth/admin/` |
| GET | `/{token}` | Reset / registration / device-add UI | Legacy entry: `/auth/{token}`; invalid tokens return `404` |
| GET | `/auth/restricted/` | HTML UI used by the auth-forward flow | Typically shown via `/auth/api/forward` on failures |

### App HTTP API: `/auth/api/*`

| Method | Path | Used for | Inputs / outputs (high level) |
|---:|---|---|---|
| POST | `/auth/api/validate` | Validate session cookie; optionally renew | Query: `perm` (repeatable). JSON response includes `valid`, `user_uuid`, `renewed` |
| GET | `/auth/api/forward` | Reverse-proxy auth check (Caddy/Nginx) | Query: `perm` (repeatable), `max_age`. Success: `204` with `Remote-*` headers; failures: `4xx` JSON or HTML depending on `Accept` |
| POST | `/auth/api/set-session` | Turn a Bearer session token into a cookie | Header: `Authorization: Bearer <session_token>`; sets cookie |
| POST | `/auth/api/logout` | Clear cookie and delete session (best-effort) | Returns JSON message |
| GET | `/auth/api/settings` | Fetch runtime settings for clients | Returns RP info + base paths + session cookie name |
| GET | `/auth/api/token-info` | Validate reset token and fetch minimal metadata | Query: `token=<token>`; invalid/expired returns `404` |
| POST | `/auth/api/user-info` | Fetch user info for UI | Either session cookie, or `reset=<token>` for reset flows |

See [Headers.md](Headers.md) for the `Remote-*` header contract used by `/auth/api/forward`.

### User account HTTP API: `/auth/api/user/*`

| Method | Path | Used for | Notes |
|---:|---|---|---|
| PUT | `/auth/api/user/display-name` | Update the user’s display name | Body: JSON `{ "display_name": "..." }` |
| POST | `/auth/api/user/logout-all` | Terminate all user sessions and clear cookie | Clears current cookie |
| DELETE | `/auth/api/user/session/{session_id}` | Terminate one session | Session IDs are server-issued |
| DELETE | `/auth/api/user/credential/{uuid}` | Delete a credential | Requires recent authentication |
| POST | `/auth/api/user/create-link` | Create a device-add link | Requires recent authentication |

### Admin HTTP API: `/auth/api/admin/*`

| Method | Path | Used for | Notes |
|---:|---|---|---|
| GET | `/auth/api/admin/` | Admin UI entry | Serves the admin SPA HTML |
| * | `/auth/api/admin/*` | Admin management API | Organizations, roles, users, permissions |

### WebSockets: `/auth/ws/*`

| Path | Used for | Notes |
|---|---|---|
| `WS /auth/ws/authenticate` | Passkey authentication | Returns a `session_token` that can be exchanged via `POST /auth/api/set-session` |
| `WS /auth/ws/register` | Register a new credential | Optional query: `reset=<token>`, `name=<display name>` |
| `WS /auth/ws/remote-auth/request` | Start a cross-device login/registration request | Returns a pairing code |
| `WS /auth/ws/remote-auth/permit` | Approve/deny a pairing code | Used from an already-authenticated device |

### Auth host mode (`--auth-host`)

| Path / type | What happens on non-auth hosts |
|---|---|
| `/auth/api/*` | Served normally |
| `/auth/api/user/*` | `404` |
| `/auth/api/admin/*` | `404` |
| `/auth/ws/*` | `404` |
| Browser UI URLs like `/admin/`, `/{token}`, and legacy `/auth/...` | `307` redirect to the auth host (UI redirects strip the `/auth` prefix) |
