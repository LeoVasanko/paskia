## Headers your app receives

When a request is allowed, the auth service adds these headers before proxying to your app (e.g., the service at `:3000`). Your app can use them for user context and authorization.

| Header | Meaning | Example |
|---|---|---|
| `Remote-User` | Authenticated user UUID | `3f1a2b3c-4d5e-6789-abcd-ef0123456789` |
| `Remote-Name` | User display name | `Jane Doe` |
| `Remote-Org` | Organization UUID | `a1b2c3d4-1111-2222-3333-444455556666` |
| `Remote-Org-Name` | Organization display name | `Acme Inc` |
| `Remote-Role` | Role UUID | `b2c3d4e5-2222-3333-4444-555566667777` |
| `Remote-Role-Name` | Role display name | `Administrators` |
| `Remote-Groups` | Comma‑separated permissions the user has | `myapp:reports,auth:admin` |
| `Remote-Session-Expires` | Session expiry timestamp (ISO 8601) | `2025-09-25T14:30:00Z` |
| `Remote-Credential` | Credential UUID backing the session | `c3d4e5f6-3333-4444-5555-666677778888` |

Note: Any incoming `Remote-*` headers from clients are stripped by our [Caddy configuration](Caddy.md), so that apps can trust these values.
