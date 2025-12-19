# Paskia API

Use these tables when integrating Paskia authentication into your app.

### Web Interface

| Method | Path | What it is for | Notes |
|---:|---|---|---|
| GET | `/auth/` | User profile page | |
| GET | `/auth/admin/` | Admin panel | Requires auth:admin (master) or org admin permissions. |
| GET | `/auth/{token}` | Reset / add credential URL (QR code link) | E.g. `/auth/fun.cotton.fresh.xray.lava` |

### Public JSON API: `/auth/api/*`

| Method | Path | Used for | Notes |
|---:|---|---|---|
| GET | `/auth/api/settings` | Paskia configuration | Returns RP info + base paths + session cookie name |
| POST | `/auth/api/user-info` | Full user profile | Basic information, credentials, sessions, permissions |
| POST | `/auth/api/logout` | Terminate session and delete session cookie | Signs out of the current site |
| POST | `/auth/api/validate` | Validate and renew session cookie | Optional query: `perm=` (repeatable) |
| GET | `/auth/api/forward` | Validate access (Caddy/Nginx) | 204 on success; 401/403 otherwise (HTML if requested) |

The `forward` endpoint takes query arguments `perm=` and `max_age=` for specific requirements on the validation of the current session.


### User JSON API: `/auth/api/user/*`

| Method | Path | Used for | Notes |
|---:|---|---|---|
| PUT | `/auth/api/user/display-name` | Update the user’s display name | Body: JSON `{ "display_name": "..." }` |
| POST | `/auth/api/user/logout-all` | Terminate all user sessions and clear cookie | Clears current cookie |
| DELETE | `/auth/api/user/session/{session_id}` | Terminate one session | Session IDs are server-issued |
| DELETE | `/auth/api/user/credential/{uuid}` | Delete a credential | Requires recent authentication |
| POST | `/auth/api/user/create-link` | Create a device-add link | Requires recent authentication |

### Admin API: `/auth/api/admin/*`

Normally only used via admin panel.

### WebSockets: `/auth/ws/*`

| Path | Used for | Notes |
|---|---|---|
| `WS /auth/ws/authenticate` | Passkey authentication | Returns a `session_token` |
| `WS /auth/ws/register` | Register a new credential | Optional query: `reset=<token>`, `name=<display name>` |
| `WS /auth/ws/remote-auth/request` | Start a cross-device login/registration request | Returns a pairing code |
| `WS /auth/ws/remote-auth/permit` | Approve/deny a pairing code | Used from an already-authenticated device |

### Auth host mode (`--auth-host`)

| Path / type | What happens on non-auth hosts |
|---|---|
| `/auth/api/*` | Served normally |
| `/auth/api/user/*` | 404 |
| `/auth/api/admin/*` | 404 |
| `/auth/ws/*` | 404 |

On the auth host itself some Web UI paths are made available at site root instead, but API stays in `/auth/api` and is fully accessible.
