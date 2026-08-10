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

You can also pass multiple scopes in one parameter by separating them with whitespace:

```text
?perm=myapp:read%20myapp:write
```

Both forms produce the same result.

## Semantics

The perm argument uses **AND** semantics: **every** listed scope must be present in the effective permissions for the request to succeed. If any required scope is missing, the endpoint returns 403.

There is **no OR** support inside a single call. If you need to check "scope A or scope B", make separate calls or check the returned permission list in your own backend.

## Wildcards

A required scope may contain the * wildcard, which matches any sequence of characters:

```text
?perm=myapp:*
```

This matches myapp:read, myapp:write, and any other scope starting with myapp:.

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
