# Paskia Trusted Headers for Apps

| HTTP Header | Meaning | Example |
|---|---|---|
| `Remote-User` | Authenticated user UUID | **01c03276-b8f0-**… (string) |
| `Remote-Name` | User display name | **John Doe** |
| `Remote-Org` | Organization UUID | Identifier for user's org (string) |
| `Remote-Org-Name` | Organization display name | `The Company Ltd.` |
| `Remote-Role` | Role UUID | Identifier for user's role (string) |
| `Remote-Role-Name` | Role display name | `Employee` |
| `Remote-Groups` | Permissions the user has, comma separated | `auth:admin,yourapp:reports` |
| `Remote-Session-Expires` | Session expiry timestamp (ISO 8601 UTC) | `2030-12-31T23:59:59Z` |
| `Remote-Credential` | Credential UUID | Identifier for the sign-in passkey (string) |

Similar headers are also used by other authentication systems like [Authelia](https://www.authelia.com/integration/trusted-header-sso/introduction/) to signal the backend application information about the signed in user.

When a request is allowed, the auth service adds these headers by the forward-auth mechanism before proxying to your app as **request headers**. Your app can use them for user context to show on UI, or for its own authentication needs (e.g. prevent different orgs messing up with each other's data, logging which user performed an action).

Only the UUID values should be used for identification needs, because they never change, even when things are renamed (display names change), and are never reused (created on authentication server). They are UUIDv7 so you can also extract the creation timestamp from them.

Any `Remote-*` headers from clients are stripped by our [Caddy configuration](Caddy.md) to avoid dealing with any fake headers.

Note: the headers are intended primarily for the backend, while either frontend or backend (passing the session cookie) can request `/auth/api/user-info` for more complete information, and that is the recommended way to do it in the frontend. See [integration](Integration.md) for more.
