# Apache APISIX Forward-Auth

[`/auth/api/forward`](../api/forward.md) · [Proxy guides](index.md)

This guide uses the Apache APISIX [`forward-auth`](https://apisix.apache.org/docs/apisix/plugins/forward-auth/) plugin to ask Paskia whether each request is allowed.

## Overview

APISIX adds the standard `X-Forwarded-*` headers automatically, but we still tell the plugin to forward `Host`, `Cookie`, and `Accept` from the client request. On a `204` response from Paskia we copy the `Remote-*` headers to the backend request.

## Admin API example

```sh
# Route that proxies /auth/ to Paskia without forward-auth.
curl "http://127.0.0.1:9180/apisix/admin/routes" -X PUT \
  -H "X-API-KEY: ${admin_key}" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "paskia-auth-ui",
    "uri": "/auth/*",
    "upstream": {
      "nodes": { "localhost:4401": 1 },
      "type": "roundrobin"
    }
  }'

# Protected route that uses Paskia forward-auth.
curl "http://127.0.0.1:9180/apisix/admin/routes" -X PUT \
  -H "X-API-KEY: ${admin_key}" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "app-protected",
    "uri": "/*",
    "priority": 10,
    "plugins": {
      "forward-auth": {
        "uri": "http://localhost:4401/auth/api/forward?perm=myapp:login",
        "request_headers": [
          "Host",
          "Cookie",
          "Accept",
          "X-Forwarded-Method",
          "X-Forwarded-Uri",
          "X-Forwarded-Host",
          "X-Forwarded-Proto",
          "X-Forwarded-For"
        ],
        "upstream_headers": [
          "Remote-User",
          "Remote-Name",
          "Remote-Groups",
          "Remote-Org",
          "Remote-Org-Name",
          "Remote-Role",
          "Remote-Role-Name",
          "Remote-Session-Expires",
          "Remote-Credential"
        ]
      }
    },
    "upstream": {
      "nodes": { "localhost:3000": 1 },
      "type": "roundrobin"
    }
  }'
```

The `paskia-auth-ui` route has a higher priority (`priority` defaults to the same value for both routes; you can also rely on the more specific `/auth/*` URI matching first). Because it does not use the `forward-auth` plugin, users can reach the login/profile pages without already being authenticated.

## ADC / declarative example

```yaml
services:
  - name: paskia-auth-ui
    routes:
      - name: auth-route
        uris:
          - /auth/*
        upstream:
          type: roundrobin
          nodes:
            - host: localhost
              port: 4401
              weight: 1

  - name: app-protected
    routes:
      - name: app-route
        uris:
          - /*
        plugins:
          forward-auth:
            uri: http://localhost:4401/auth/api/forward?perm=myapp:login
            request_headers:
              - Host
              - Cookie
              - Accept
              - X-Forwarded-Method
              - X-Forwarded-Uri
              - X-Forwarded-Host
              - X-Forwarded-Proto
              - X-Forwarded-For
            upstream_headers:
              - Remote-User
              - Remote-Name
              - Remote-Groups
              - Remote-Org
              - Remote-Org-Name
              - Remote-Role
              - Remote-Role-Name
              - Remote-Session-Expires
              - Remote-Credential
        upstream:
          type: roundrobin
          nodes:
            - host: localhost
              port: 3000
              weight: 1
```

Apply it with:

```sh
adc sync -f paskia.yaml
```

## What APISIX sends to Paskia

APISIX automatically adds these headers to the auth request:

| Header | Value |
|---|---|
| `X-Forwarded-Method` | Original HTTP method |
| `X-Forwarded-Proto` | Request scheme (`http`/`https`) |
| `X-Forwarded-Host` | Original host |
| `X-Forwarded-Uri` | Original request URI |
| `X-Forwarded-For` | Client IP address |

We list them again in `request_headers` to make sure they are not accidentally filtered out when the list is explicit.

## Response headers

`upstream_headers` lists the `Remote-*` headers that APISIX copies from the auth response to the backend request. The plugin does not support a wildcard here, so each header must be named.

If you want Paskia's failure-response headers (such as `Content-Type` or `Set-Cookie`) to reach the client, list them in `client_headers`. For Paskia this is usually not needed; the response body already contains the JSON auth URL or the HTML login page.

## Adjusting requirements

Change the `uri` query string to require different permissions or recent authentication:

```yaml
uri: http://localhost:4401/auth/api/forward?perm=myapp:login
uri: http://localhost:4401/auth/api/forward?perm=myapp:admin&max_age=5min
uri: http://localhost:4401/auth/api/forward
```

The last form requires only authentication. See [perm argument](../api/perm.md) and [max_age argument](../api/max-age.md).

## Notes

- The auth request is `GET` by default. Since the `forward-auth` plugin does not forward the request body unless `request_method` is set to `POST`, the default `GET` is the right choice for Paskia.
- Hop-by-hop headers are handled by APISIX when it builds the auth request, so no extra configuration is needed for `Connection`/`Upgrade`.
- If Paskia is running on a different host, replace `localhost:4401` with the Paskia service address. For a dedicated authentication host (`--auth-host`), route `auth.example.com` to Paskia instead of `/auth/`.
