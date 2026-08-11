# POST /auth/api/validate

[API overview](../API.md) · [`/auth/api/forward`](../forward.md) · [max_age](max-age.md) · [perm](perm.md)

Validate a session and renew its lifetime when needed. This endpoint is normally called by the browser/session validator, but backends may also call it directly when not behind a forward-auth proxy.

See also the [API overview](../API.md) and the [integration guide](../Integration.md).

## Query parameters

| Parameter | Description |
|-----------|-------------|
| perm | Required permissions. See the [perm argument](perm.md). |
| max_age | Require recent passkey use. See the [max_age argument](max-age.md). |

## Request headers

| Header | Expected value / note | How Paskia uses it |
|---|---|---|
| Host | Forwarded directly from the client | Verifying the session's bound host |
| Cookie | Forwarded directly or just cookie `__Host-paskia` | Session ID |
| X-Forwarded-For | Real client IP | Recorded in session data instead of the backend/proxy IP; requires FORWARDED_ALLOW_IPS to trust the immediate peer |
| User-Agent | Forward the original client UA if available; do not let your backend client add its own default | Recorded in session data only when the header is present; omitting it preserves the existing value |

See [integration documentation for backend validate requests](../Integration.md) for more detailed instructions, in particular for forwarding of client-provided headers.

## Response

The endpoint always responds with JSON.

### Success (200)

```json
{
  "valid": true,
  "renewed": false,
  "ctx": {
    "user": {
      "uuid": "...",
      "display_name": "John Smith",
      "theme": "dark"
    },
    "org": {
      "uuid": "...",
      "display_name": "The Company Ltd."
    },
    "role": {
      "uuid": "...",
      "display_name": "Employee"
    },
    "permissions": ["auth:admin", "myapp:login"]
  }
}
```

If the response includes a Set-Cookie header, the session has been renewed (renewed is true) and you should forward that cookie to the client so the browser updates its expiry. Not forwarding it means the session lifetime is not extended, so the user may need to re-authenticate sooner. Renewals are throttled, so frequent calls usually return renewed: false with no Set-Cookie.

### Failure (400 / 401 / 403)

| Status | Meaning |
|---|---|
| 400 | Malformed perm argument (see [perm](perm.md#syntax-errors)). |
| 401 | Session missing, expired, or max_age not satisfied. The response body includes auth metadata for the login/reauth iframe. |
| 403 | Session is valid but one or more requested permissions are missing. |

A failure response never contains a refreshed Set-Cookie.
