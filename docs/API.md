# Paskia API

[Integration](Integration.md) · [Proxy guides](proxy/index.md)

For integrating Paskia with your app frontend, see [integration](Integration.md).

## Web Interface

| Method | Path | What it is for | Responses |
|---:|---|---|---|
| GET | /auth/ | User profile page | HTML 200/401 |
| GET | /auth/admin/ | Admin panel, requires auth:admin or org admin permissions | HTML 200/401/403 |
| GET | /auth/{token} | Reset / add credential URL (QR code link), e.g. /auth/fun.cotton.fresh.xray.lava | HTML 200 |

### Public JSON API: /auth/api/*

| Method | Path | Used for | Responses |
|---:|---|---|---|
| GET | /auth/api/settings | Paskia configuration: RP info, base paths, session cookie name | 200 |
| GET | /auth/api/user-info | Full user profile: info, credentials, sessions, permissions | 200/401 |
| POST | /auth/api/logout | Terminate session and delete session cookie on the current host | 200 |
| POST | [/auth/api/validate](api/validate.md) | Validate and renew the session cookie; query [perm](api/perm.md), [max_age](api/max-age.md) | 200/401/403 |
| GET | [/auth/api/forward](api/forward.md) | Forward-auth with reverse proxies; see [proxy guides](proxy/index.md), query [perm](api/perm.md), [max_age](api/max-age.md) | 204/401/403 empty, json or html|

### User JSON API: /auth/api/user/*

| Method | Path | Used for | Responses |
|---:|---|---|---|
| PATCH | /auth/api/user/display-name | Update the user's display name | 200/401 |
| POST | /auth/api/user/logout-all | Terminate all user sessions | 200/401 |
| DELETE | /auth/api/user/session/{session_id} | Terminate one session | 200/401 |
| DELETE | /auth/api/user/credential/{uuid} | Delete a credential; requires recent authentication | 200/401/403 |
| POST | /auth/api/user/create-link | Create a device-add link; requires recent authentication | 200/401/403 |
| GET | /auth/api/user/{uuid}/profile.webp | Canonical avatar image URL, public on the auth host | 200/304/404 |
| PUT | /auth/api/user/{uuid}/profile.webp | Upload or replace an avatar; square WebP prepared in the browser | 200/401/403 |
| DELETE | /auth/api/user/{uuid}/profile.webp | Remove an avatar; allowed for the user or an admin | 200/401/403 |

These are used mostly from the user profile panel by the user himself, but the profile pictures are public for all to read.

### Admin API: /auth/api/admin/*

Normally only used via admin panel, requires auth admin permissions and can modify any users, orgs and permissions the session has access to.

E.g. Org admin cannot see anything of the other orgs that he has no admin access to. Master admin auth:admin can see everything and create and manage orgs.

| Method | Path | Used for | Responses |
|---:|---|---|---|
| GET | /auth/api/admin/info | Admin overview: orgs, permissions, OIDC clients | 200/401/403 |
| POST | /auth/api/admin/permissions/ | Create permission | 200/401/403 |
| PATCH | /auth/api/admin/permissions/{uuid} | Update permission | 200/401/403 |
| DELETE | /auth/api/admin/permissions/{uuid} | Delete permission | 200/401/403 |
| POST | /auth/api/admin/orgs/ | Create organization | 200/401/403 |
| GET | /auth/api/admin/orgs/{uuid} | Get organization details | 200/401/403 |
| PATCH | /auth/api/admin/orgs/{uuid} | Update organization | 200/401/403 |
| DELETE | /auth/api/admin/orgs/{uuid} | Delete organization | 200/401/403 |
| POST | /auth/api/admin/orgs/{uuid}/users | Create user in org | 200/401/403 |
| POST | /auth/api/admin/orgs/{uuid}/roles | Create role in org | 200/401/403 |
| POST | /auth/api/admin/orgs/{uuid}/permission | Grant permission to org | 200/401/403 |
| DELETE | /auth/api/admin/orgs/{uuid}/permission | Revoke permission from org | 200/401/403 |
| PATCH | /auth/api/admin/roles/{uuid} | Update role | 200/401/403 |
| POST | /auth/api/admin/roles/{uuid}/permissions/{uuid} | Add permission to role | 200/401/403 |
| DELETE | /auth/api/admin/roles/{uuid}/permissions/{uuid} | Remove permission from role | 200/401/403 |
| DELETE | /auth/api/admin/roles/{uuid} | Delete role | 200/401/403 |
| PATCH | /auth/api/admin/users/{uuid}/role | Update user role | 200/401/403 |
| PATCH | /auth/api/admin/users/{uuid}/info | Update user info | 200/401/403 |
| GET | /auth/api/admin/users/{uuid} | Get user details | 200/401/403 |
| DELETE | /auth/api/admin/users/{uuid} | Delete user | 200/401/403 |
| POST | /auth/api/admin/users/{uuid}/create-link | Create device add link | 200/401/403 |
| DELETE | /auth/api/admin/users/{uuid}/credentials/{uuid} | Delete user credential | 200/401/403 |
| DELETE | /auth/api/admin/users/{uuid}/sessions/{key} | Delete user session | 200/401/403 |
| POST | /auth/api/admin/oidc-clients/ | Create OIDC client | 200/401/403 |
| PATCH | /auth/api/admin/oidc-clients/{uuid} | Update OIDC client | 200/401/403 |
| PATCH | /auth/api/admin/oidc-clients/{uuid}/reset-secret | Reset client secret | 200/401/403 |
| DELETE | /auth/api/admin/oidc-clients/{uuid} | Delete OIDC client | 200/401/403 |
| GET | /auth/api/admin/server-config/ | Get server config | 200/401/403 |
| PATCH | /auth/api/admin/server-config/ | Update server config | 200/401/403 |

### WebSockets: /auth/ws/*

| Path | Used for | Notes |
|---|---|---|
| WS /auth/ws/authenticate | Passkey authentication | Returns a session token |
| WS /auth/ws/register | Register a new credential | Adding another passkey to current user or via reset token |
| WS /auth/ws/remote-auth/request | Start a cross-device login/registration request | Used from unauthenticated client |
| WS /auth/ws/remote-auth/permit | Approve/deny a pairing code | Used to accept the request, if same words are entered |

These are for internal use only, but are documented here because they are the core piece in all passkey operations.

### Auth host mode (--auth-host)

#### On the auth host:
- The Web UI is served at site root instead of /auth/* (that redirects to root paths)
- All of the API stays under /auth/api/*
- Auth WebSockets remain at /auth/ws/* but take connections from other hosts to issue sessions for each of those.

#### On non-auth hosts:
- /auth/ shows only minimal profile and allows logging out of the current site, link to full profile on auth host
- /auth/api/* is served normally.
- /auth/api/user/*, /auth/api/admin/*, and /auth/ws/* don't exist.

The WebSocket connections are directed to auth host, and must have an allowed origin corresponding to the host where the user is logging in, that the session is tied with.
