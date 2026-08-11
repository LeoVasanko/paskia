# The perm argument

[API overview](../API.md) · [`/auth/api/validate`](validate.md) · [`/auth/api/forward`](../forward.md)

The perm argument is used by endpoints that validate sessions to require one or more permission scopes. It is supported by:

- [POST /auth/api/validate](validate.md)
- [GET /auth/api/forward](forward.md)

## Passing the argument

Repeat the query parameter for each required scope:

```text
?perm=myapp:read&perm=myapp:write
```

You can also pass multiple scopes in one parameter by separating them with whitespace (a literal space, i.e. `+` or `%20` in the query string):

```text
?perm=myapp:read%20myapp:write
```

Both forms produce the same result.

## Semantics

The perm argument uses **AND** semantics between groups: **every** listed scope group must be satisfied by the effective permissions for the request to succeed. If any required group is not satisfied, the endpoint returns 403.

Within a single group, use `|` to list alternatives with **OR** semantics — the group is satisfied when **any one** of the alternatives is present:

```text
?perm=myapp:read|myapp:write+myapp:login
```

This requires `myapp:login` **and** (`myapp:read` **or** `myapp:write`). No whitespace is allowed around the `|` operator.

## Syntax errors

Parsing is strict: anything out of spec is rejected with **400 Bad Request** rather than guessed at. This includes:

- Empty values or alternatives (`?perm=`, `?perm=a||b`, `?perm=|a`, `?perm=a|`)
- Whitespace around `|` (`?perm=a+|+b`)
- Characters not allowed in scopes other than the operators (space and `|`); scopes match `^[A-Za-z0-9:._~/-]+$` plus the `*` wildcard. In particular a literal `+` in the decoded value (from a `%2B` in the query string) is rejected — use `+` or `%20` to encode a space, never `%2B`.

Extra spaces between groups (leading, trailing, or repeated) are tolerated, since they can easily result from URL formatting and carry no ambiguity — they only ever add required permissions, never remove them. The `|` operator is parsed strictly: `?perm=foo&perm=|bar` is an error, never a way to make `foo` optional.

## Wildcards

Wildcards work like filenames, with `:` and `/` acting as path separators:

- `*` matches any sequence of characters **within a single segment** (it never crosses a `:` or `/`)
- `**` matches any sequence of characters, **across separators**
- Part of a segment can be wildcarded, with required text on either or both sides

```text
?perm=myapp:*
```

This matches myapp:read and myapp:write, but **not** myapp:read:all — use `myapp:**` for that. Partial wildcards like `myapp:re*` or `myapp:r*d` match myapp:read. The same applies to path-based scopes: `myapp:path:/api/*` matches myapp:path:/api/clients but not myapp:path:/api/v2/clients — use `myapp:path:/api/**` to span path segments.

## Effective permissions

The permissions available to a session are determined as follows:

1. **Role permissions** — the role assigned to the user contains a set of permission UUIDs.
2. **Org grantable permissions** — only permissions that the user's organization is allowed to grant are effective.
3. **Domain filtering** — a permission can be restricted to a specific domain via its domain field. If the request's Host header does not match that domain, the permission is excluded.

The result is the set of effective permission scopes used for the perm check. Domain-restricted permissions let you grant a scope only for a specific site or subdomain without making it global.

## Examples

Require a single permission:

```text
?perm=myapp:login
```

Require two permissions:

```text
?perm=myapp:login&perm=myapp:api
```

Require any scope under myapp:

```text
?perm=myapp:*
```

Require myapp:login and either myapp:read or myapp:write:

```text
?perm=myapp:login&perm=myapp:read|myapp:write
```
