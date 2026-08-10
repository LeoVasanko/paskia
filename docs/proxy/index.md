# Forward-Auth Proxy Guides

[`/auth/api/forward`](../api/forward.md) · [Trusted headers](../Headers.md)

These guides show how to protect a backend application with Paskia using the forward-auth (also called "external authentication") mechanism. The reverse proxy asks Paskia whether a request is allowed before forwarding it to the protected service.

For details about the endpoint the proxy calls, see [`/auth/api/forward`](../api/forward.md). For the headers your backend receives on successful requests, see [Trusted Headers](../Headers.md).

## Available guides

- [Caddy](caddy.md) — fully supported with ready-to-use snippets (`auth/setup` and `auth/require`).
- [Nginx](nginx.md) — using the `auth_request` module.
- [Traefik](traefik.md) — using the `ForwardAuth` middleware.
- [Apache APISIX](apisix.md) — using the `forward-auth` plugin.
- [Envoy](envoy.md) — using the `ext_authz` HTTP filter.
- [HAProxy](haproxy.md) — using a Lua auth request.

## Common requirements

No matter which proxy you use, the auth subrequest must:

1. Be sent to `GET /auth/api/forward` on the Paskia backend. By default Paskia listens on `localhost:4401`; set the `AUTH_UPSTREAM` environment variable in our Caddy snippets, or point your proxy at wherever Paskia is running.
2. Include the query parameters Paskia needs for access control:
   - `perm` — required permission scope, repeatable (e.g. `perm=myapp:login`). See [perm argument](../api/perm.md).
   - `max_age` — how recently the user must have authenticated (e.g. `max_age=5min`). See [max_age argument](../api/max-age.md).
3. Forward these request headers from the original client request:
   - `Host` — the site the user is visiting.
   - `Cookie` — the session cookie, normally `__Host-paskia`.
   - `X-Forwarded-Method` — the original HTTP method (e.g. `GET`, `POST`).
   - `X-Forwarded-Uri` — the original path and query string (e.g. `/reports?foo=bar`).
   - `Accept` — decides whether a 401/403 response should be HTML (browser) or JSON (API/fetch).
4. Strip hop-by-hop headers (`Connection`, `Upgrade`, `Transfer-Encoding`, `Keep-Alive`, `Proxy-Connection`, `TE`) from the auth subrequest. The auth check is a plain HTTP request and must not carry WebSocket/body framing headers.
5. On a `204 No Content` response, copy the `Remote-*` response headers to the request that is forwarded to the protected backend. The headers are the whole point of the auth check.
6. On a 401/403 response, send Paskia's response back to the client without contacting the protected backend.
7. Also proxy the `/auth/` path prefix to Paskia so the login/profile UI, API endpoints, and WebSockets are reachable. Paskia's WebSocket endpoints need `Upgrade` and `Connection` headers passed through for that path.

## Backend usage

After the proxy forwards the request, your backend can read the trusted headers. For example, in Python/FastAPI:

```python
user_id = request.headers.get("Remote-User")
org_id = request.headers.get("Remote-Org")
permissions = request.headers.get("Remote-Groups", "").split(",")
```

Only trust headers that come from the proxy; never trust `Remote-*` headers that arrive directly from the internet. Your proxy configuration should strip any client-supplied `Remote-*` headers before the auth check.
