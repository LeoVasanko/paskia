# Traefik ForwardAuth

[`/auth/api/forward`](../api/forward.md) · [Proxy guides](index.md)

This guide uses Traefik's [ForwardAuth middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/) to ask Paskia whether each request is allowed.

## Overview

A typical dynamic (YAML) configuration looks like this:

```yaml
http:
  routers:
    app:
      rule: "Host(`app.example.com`)"
      service: app-backend
      middlewares:
        - paskia-auth

    # Route /auth/ straight to Paskia, bypassing the auth middleware.
    auth:
      rule: "Host(`app.example.com`) && PathPrefix(`/auth/`)"
      service: paskia
      middlewares: []

  middlewares:
    paskia-auth:
      forwardAuth:
        address: "http://localhost:4401/auth/api/forward?perm=myapp:login"
        # Forward every Remote-* header from the auth response to the backend.
        authResponseHeadersRegex: "^Remote-"
        # Explicitly pass the headers Paskia needs. If left empty, all headers
        # are forwarded; being explicit avoids accidentally leaking hop-by-hop
        # headers to the auth server.
        authRequestHeaders:
          - Host
          - Cookie
          - Accept
          - X-Forwarded-Method
          - X-Forwarded-Uri
          - X-Forwarded-Host
          - X-Forwarded-Proto
          - X-Forwarded-For

  services:
    app-backend:
      loadBalancer:
        servers:
          - url: "http://localhost:3000"

    paskia:
      loadBalancer:
        servers:
          - url: "http://localhost:4401"
```

## What Traefik sends automatically

Traefik's ForwardAuth middleware sends the auth request to the configured `address` and includes the following headers derived from the original request:

| Header | Value |
|---|---|
| `X-Forwarded-Method` | Original HTTP method |
| `X-Forwarded-Proto` | Original protocol (`http`/`https`) |
| `X-Forwarded-Host` | Original host |
| `X-Forwarded-Uri` | Original request URI (path and query) |
| `X-Forwarded-For` | Client IP address |

These are exactly the headers Paskia logs. You should still include them in `authRequestHeaders` if you set that list explicitly, to make sure they are not filtered out.

## Response headers

`authResponseHeadersRegex: "^Remote-"` tells Traefik to copy every response header starting with `Remote-` from Paskia's `204` response and add it to the request that is forwarded to your backend. It also strips any `Remote-*` headers that the client may have sent, so the backend can trust the values.

For stricter control, you can list the headers explicitly instead of using the regex:

```yaml
authResponseHeaders:
  - Remote-User
  - Remote-Name
  - Remote-Groups
  - Remote-Org
  - Remote-Org-Name
  - Remote-Role
  - Remote-Role-Name
  - Remote-Session-Expires
  - Remote-Credential
```

## Proxying `/auth/` to Paskia

The `/auth/` router above forwards all authentication UI, API, and WebSocket traffic to Paskia. Because this router does **not** use the `paskia-auth` middleware, users can reach the login page and profile UI without being authenticated first. Traefik handles WebSocket upgrades automatically when the client requests them.

If you are using a dedicated authentication host instead of `/auth/`, create a separate router for `auth.example.com` pointing to the Paskia service and start Paskia with `--auth-host auth.example.com`.

## Adjusting requirements

Change the `address` query string to require different permissions or recent authentication:

```yaml
address: "http://localhost:4401/auth/api/forward?perm=myapp:login"
address: "http://localhost:4401/auth/api/forward?perm=myapp:admin&max_age=5min"
address: "http://localhost:4401/auth/api/forward"
```

The last form requires only authentication, no specific permission. See [perm argument](../api/perm.md) and [max_age argument](../api/max-age.md).

## Docker labels example

When using Traefik with Docker Compose, you can define the middleware with labels:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.myapp.rule=Host(`app.example.com`)"
  - "traefik.http.routers.myapp.middlewares=paskia-auth"
  - "traefik.http.middlewares.paskia-auth.forwardauth.address=http://localhost:4401/auth/api/forward?perm=myapp:login"
  - "traefik.http.middlewares.paskia-auth.forwardauth.authResponseHeadersRegex=^Remote-"
  - "traefik.http.middlewares.paskia-auth.forwardauth.authRequestHeaders=Host,Cookie,Accept,X-Forwarded-Method,X-Forwarded-Uri"
```

## Notes

- By default ForwardAuth sends a request without the original body. If you need to forward the body for logging/validation, set `forwardBody: true` and a sensible `maxBodySize`, but for Paskia this is not required.
- Paskia does not set cookies on the forward-auth response; it only returns `Remote-*` headers. Use the JavaScript helpers from the [paskia](https://www.npmjs.com/package/paskia) package for session renewal in the frontend.
- For HTTPS, use `https://` in the `address` and configure TLS options (`tls.insecureSkipVerify: true` only for testing).
