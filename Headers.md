## Trusted Headers for Apps

| HTTP Header | Meaning | Example |
|---|---|---|
| `Remote-User` | Authenticated user UUID | Unique string |
| `Remote-Name` | User display name | `John Doe` |
| `Remote-Org` | Organization UUID | Identifier for org (string) |
| `Remote-Org-Name` | Organization display name | `The Company Ltd.` |
| `Remote-Role` | Role UUID | Identifier for user's role (string) |
| `Remote-Role-Name` | Role display name | `Employee` |
| `Remote-Groups` | Permissions the user has, separated by commas | `auth:admin,yourapp:reports` |
| `Remote-Session-Expires` | Session expiry timestamp (ISO 8601 UTC) | `2030-12-31T23:59:59Z` |
| `Remote-Credential` | Credential UUID | Identifier for the currently signed in passkey (string) |

Similar headers are also used by other authentication systems like [Authelia](https://www.authelia.com/integration/trusted-header-sso/introduction/) to signal the backend application information about the signed in user.

When a request is allowed, the auth service adds these headers by the forward-auth mechanism before proxying to your app as **request headers**. Your app can use them for user context to show on UI, or for its own authentication needs (e.g. prevent different orgs messing up with each other's data, logging which user performed an action).

Only the UUID values should be used for identification needs, because they never change, even when things are renamed (display names change), and are never reused (created on authentication server). They are UUIDv7 so you can also extract the creation timestamp from them.

Any `Remote-*` headers from clients are stripped by our [Caddy configuration](Caddy.md) so that apps can trust these values.
