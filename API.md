# Paskia API

For integrating Paskia with your app frontend, see [integration](Integration.md).

## Web Interface

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
| POST | `/auth/api/validate` | Validate and renew session cookie | Optional query: `perm=` (repeatable), `max_age=` |
| GET | `/auth/api/forward` | Validate access (Caddy/Nginx) | 204 on success; 401/403 otherwise (HTML if requested) |

The `validate` and `forward` endpoints take query arguments `perm=` and `max_age=` for specific requirements on the validation of the current session.

### User JSON API: `/auth/api/user/*`

| Method | Path | Used for | Notes |
|---:|---|---|---|
| PUT | `/auth/api/user/display-name` | Update the user’s display name | Body: JSON `{ "display_name": "..." }` |
| POST | `/auth/api/user/logout-all` | Terminate all user sessions | Clears current host cookie |
| DELETE | `/auth/api/user/session/{session_id}` | Terminate one session | Session IDs are server-issued |
| DELETE | `/auth/api/user/credential/{uuid}` | Delete a credential | Requires recent authentication |
| POST | `/auth/api/user/create-link` | Create a device-add link | Requires recent authentication |

These are used mostly from the user profile panel and modify the current user.

### Admin API: `/auth/api/admin/*`

Normally only used via admin panel, requires auth admin permissions and can modify any users, orgs and permissions the session has access to.

E.g. Org admin cannot see anything of the other orgs that he has no admin access to. Master admin `auth:admin` can see everything and create and manage orgs.

### WebSockets: `/auth/ws/*`

| Path | Used for | Notes |
|---|---|---|
| `WS /auth/ws/authenticate` | Passkey authentication | Returns a session token |
| `WS /auth/ws/register` | Register a new credential | Adding another passkey to current user or via reset token |
| `WS /auth/ws/remote-auth/request` | Start a cross-device login/registration request | Used from unauthenticated client |
| `WS /auth/ws/remote-auth/permit` | Approve/deny a pairing code | Used to accept the request, if same words are entered |

These are for internal use only, but are documented here because they are the core piece in all passkey operations.

### Auth host mode (`--auth-host`)

#### On the auth host:
- The Web UI is served at site root (e.g. admin UI at `/admin/`), and the `/auth/...` equivalents (e.g. `/auth/admin/`) redirect to the root paths.
- All of the API stays under `/auth/api/*`
- Auth WebSockets remain at `/auth/ws/*` but take connections from other hosts to issue sessions for each of those.

#### On non-auth hosts:
- `/auth/` shows only minimal profile and allows logging out of the current site
- `/auth/api/*` is served normally.
- `/auth/api/user/*`, `/auth/api/admin/*`, and `/auth/ws/*` don't exist.
