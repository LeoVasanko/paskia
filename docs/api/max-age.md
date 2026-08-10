# The max_age argument

[API overview](../API.md) · [`/auth/api/validate`](validate.md) · [`/auth/api/forward`](../forward.md)

The max_age argument is used by endpoints that validate sessions to require a recent passkey use. It is supported by:

- [POST /auth/api/validate](validate.md)
- [GET /auth/api/forward](forward.md)

## What it checks

max_age limits how long ago the user last authenticated with their passkey. It is intended for high-risk actions where you want to be sure the user recently proved possession of their credential, not just that they still have a valid session cookie.

The check compares the elapsed time since the credential was last used against the given limit:

- If the credential has a last_used timestamp, that time is used.
- Otherwise, the session's validated timestamp is used as a fallback.

If the authentication is older than max_age, the endpoint returns 401 with mode reauth, prompting the user to re-authenticate.

## Time units

max_age accepts a number followed by one of these units:

| Unit | Meaning |
|---|---|
| s | seconds |
| m / min | minutes |
| h | hours |
| d | days |

Examples:

```text
?max_age=30s
?max_age=5m
?max_age=5min
?max_age=1h
?max_age=1d
```

An invalid format is logged as a warning but does not cause the request to fail; the requirement is simply ignored in that case.

## Important notes

- Session renewal by /auth/api/validate does **not** count as fresh authentication. The check is based on the credential's last_used time, not on how recently the session cookie was renewed.
- max_age is independent of perm. You can use either or both at the same time.
