# HAProxy Forward-Auth

[`/auth/api/forward`](../api/forward.md) · [Proxy guides](index.md)

HAProxy does not have a built-in forward-auth primitive, but the community [`haproxy-auth-request`](https://github.com/TimWolla/haproxy-auth-request) Lua script provides an `auth-intercept` action that works very similarly to Nginx's `auth_request`. It makes an internal HTTP request to Paskia and copies the response headers to the backend request.

## Requirements

- HAProxy 2.2 or newer (2.0+ may work but 2.2+ supports all features shown here).
- Compiled with `USE_LUA=1`.
- The [`haproxy-auth-request`](https://github.com/TimWolla/haproxy-auth-request) Lua script loaded.
- The [`haproxy-lua-http`](https://github.com/haproxytech/haproxy-lua-http) dependency in the Lua path.

## Overview

```haproxy
global
    lua-load /usr/share/haproxy/auth-request.lua

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Backend that runs the Paskia auth check.
backend paskia_auth
    server paskia 127.0.0.1:4401

# Backend that runs the Paskia UI / WebSocket / API.
backend paskia_ui
    server paskia 127.0.0.1:4401

# Your protected application.
backend app_backend
    server app 127.0.0.1:3000

frontend app
    bind *:80

    # 1. Route /auth/ straight to Paskia, bypassing the auth check.
    acl is_auth path_beg /auth/
    use_backend paskia_ui if is_auth

    # 2. Add the headers Paskia logs / expects. These are then copied to the
    #    auth subrequest by auth-intercept.
    http-request set-header X-Forwarded-Method %[method]
    http-request set-header X-Forwarded-Uri %[url]

    # 3. Run the auth check. The parameters are:
    #    backend       path                                   method
    #    req-headers   success-headers                        failure-headers
    #
    #    - req-headers:   headers copied from client to Paskia.
    #    - success-headers: headers copied from Paskia response to backend request.
    #    - failure-headers: headers copied from Paskia response to client response.
    http-request lua.auth-intercept paskia_auth /auth/api/forward?perm=myapp:login GET Host,Cookie,Accept,X-Forwarded-Method,X-Forwarded-Uri Remote-* *

    # 4. If the subrequest was not successful, deny the request.
    http-request deny if ! { var(txn.auth_response_successful) -m bool }

    default_backend app_backend
```

## What the configuration does

1. **Route `/auth/` to Paskia** — users must be able to reach the login/profile UI without already being authenticated. HAProxy will proxy WebSocket upgrade headers automatically for this backend when the client requests them.
2. **Set `X-Forwarded-Method` and `X-Forwarded-Uri`** — HAProxy adds these headers to the incoming request so the Lua script can copy them to the auth subrequest. `%[method]` returns the HTTP method and `%[url]` returns the path and query string.
3. **`lua.auth-intercept`** — sends a `GET` request to `/auth/api/forward?perm=myapp:login` on the `paskia_auth` backend. It copies the listed request headers (including the dynamic ones we just set) to the auth subrequest.
4. **On success (`2xx`)** — copies every response header matching `Remote-*` from Paskia to the backend request. This overrides any client-supplied `Remote-*` headers, so the backend can trust them.
5. **On failure (`4xx`)** — copies all response headers (`*`) to the client response and uses Paskia's response body, so the browser gets the login HTML or the JSON auth URL.
6. **Deny if auth failed** — the final `http-request deny` rule is a safety net. In practice, `auth-intercept` with `*` as the failure-headers already terminates the transaction with Paskia's response.

## Backend definition for the auth subrequest

The `paskia_auth` backend can be the same physical server as `paskia_ui`, but using a separate backend is convenient because the Lua script will use the first available server in the backend. The auth subrequest is a plain HTTP request, so no special WebSocket options are needed here.

```haproxy
backend paskia_auth
    server paskia 127.0.0.1:4401
```

## Per-route permissions

You can run different auth checks for different paths by using HAProxy ACLs. Place the more specific rules before the generic one:

```haproxy
frontend app
    bind *:80

    acl is_auth path_beg /auth/
    use_backend paskia_ui if is_auth

    acl is_reports path_beg /reports
    http-request set-header X-Forwarded-Method %[method] if is_reports
    http-request set-header X-Forwarded-Uri %[url] if is_reports
    http-request lua.auth-intercept paskia_auth /auth/api/forward?perm=myapp:reports&max_age=5min GET Host,Cookie,Accept,X-Forwarded-Method,X-Forwarded-Uri Remote-* * if is_reports

    http-request set-header X-Forwarded-Method %[method]
    http-request set-header X-Forwarded-Uri %[url]
    http-request lua.auth-intercept paskia_auth /auth/api/forward?perm=myapp:login GET Host,Cookie,Accept,X-Forwarded-Method,X-Forwarded-Uri Remote-* *

    http-request deny if ! { var(txn.auth_response_successful) -m bool }
    default_backend app_backend
```

See [perm argument](../api/perm.md) and [max_age argument](../api/max-age.md) for query parameter syntax.

## Notes

- The Lua script strips the request body from the auth subrequest, so Paskia's `/auth/api/forward` will only see the headers.
- HAProxy variables are limited to alphanumeric characters, dots, and underscores, but the script already normalizes header names for you (e.g. `Remote-User` becomes `req.auth_response_header.remote_user`). The `Remote-*` glob pattern in the success-headers argument handles this automatically.
- The auth backend must be reachable without TLS. If you need TLS to Paskia, run a local TCP forwarder or use HAProxy's Lua HTTP support directly (not covered by this script).
- If you use a dedicated authentication host (`--auth-host`), route `auth.example.com` to the Paskia backend and start Paskia with `--auth-host auth.example.com` instead of exposing `/auth/` on every site.
