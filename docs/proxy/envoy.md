# Envoy External Authorization (ext_authz)

[`/auth/api/forward`](../api/forward.md) · [Proxy guides](index.md)

This guide uses Envoy's [external authorization filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) (`ext_authz`) to ask Paskia whether each request is allowed.

## Overview

Envoy's `ext_authz` HTTP filter calls an external HTTP service before forwarding a request to the upstream. The filter needs to know which headers from the original request to send to Paskia, and which headers from Paskia's response to add to the upstream request or to the client response.

A minimal static configuration looks like this:

```yaml
static_resources:
  listeners:
    - name: app_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                use_remote_address: true
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: app
                      domains: ["*"]
                      routes:
                        # Pass /auth/ straight to Paskia, bypassing ext_authz.
                        - match:
                            prefix: "/auth/"
                          route:
                            cluster: paskia
                          typed_per_filter_config:
                            envoy.filters.http.ext_authz:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                              disabled: true

                        # Protect everything else.
                        - match:
                            prefix: "/"
                          route:
                            cluster: app_backend
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: v3
                      http_service:
                        server_uri:
                          uri: localhost:4401
                          cluster: paskia
                          timeout: 0.5s
                        # Send every auth check to /auth/api/forward with the
                        # required permission, regardless of the original path.
                        path_override: "/auth/api/forward?perm=myapp:login"
                        authorization_request:
                          allowed_headers:
                            patterns:
                              - exact: Host
                              - exact: Cookie
                              - exact: Accept
                          # Add the headers Paskia logs / expects.
                          headers_to_add:
                            - key: X-Forwarded-Method
                              value: "%REQ(:METHOD)%"
                            - key: X-Forwarded-Uri
                              value: "%REQ(:PATH)%"
                            - key: X-Forwarded-Proto
                              value: "%REQ(:SCHEME)%"
                            - key: X-Forwarded-For
                              value: "%REQ(X-Forwarded-For)%"
                        authorization_response:
                          # Forward every Remote-* header to the backend.
                          allowed_upstream_headers:
                            patterns:
                              - prefix: Remote-
                          # Forward the response Content-Type to the client on 401/403.
                          allowed_client_headers:
                            patterns:
                              - exact: Content-Type
                      failure_mode_allow: false
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: app_backend
      connect_timeout: 0.25s
      type: logical_dns
      lb_policy: round_robin
      load_assignment:
        cluster_name: app_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: localhost
                      port_value: 3000

    - name: paskia
      connect_timeout: 0.25s
      type: logical_dns
      lb_policy: round_robin
      load_assignment:
        cluster_name: paskia
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: localhost
                      port_value: 4401
```

## Important configuration details

- **`path_override`** — the auth request always goes to `/auth/api/forward?perm=myapp:login`, no matter which path the client requested. The original path is sent in `X-Forwarded-Uri` for Paskia to log.
- **`authorization_request.allowed_headers`** — Envoy only forwards the headers you explicitly allow. We allow `Host`, `Cookie`, and `Accept`. The `X-Forwarded-*` headers are added via `headers_to_add` so they are based on Envoy's view of the request, not spoofed client values.
- **`headers_to_add`** — Envoy supports substitution format strings such as `%REQ(:METHOD)%` and `%REQ(:PATH)%`. These set the headers Paskia uses for logging and host validation.
- **`authorization_response.allowed_upstream_headers`** — `prefix: Remote-` tells Envoy to copy every response header starting with `Remote-` to the upstream request. This also removes any client-supplied `Remote-*` headers, so the backend can trust them.
- **`authorization_response.allowed_client_headers`** — on a 401/403 response, Envoy forwards only the allowed response headers to the client. Paskia returns HTML or JSON with a `Content-Type` header, so we allow that. (Paskia does not set cookies on the forward-auth response.)
- **`typed_per_filter_config`** on the `/auth/` route disables `ext_authz` so users can reach the login/profile pages without already being authenticated.

## Per-route requirements

Different routes often need different permissions or `max_age` values. Use `typed_per_filter_config` on each route to override the `http_service.path_override`:

```yaml
routes:
  - match:
      prefix: "/reports"
    route:
      cluster: app_backend
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        check_settings:
          http_service:
            path_override: "/auth/api/forward?perm=myapp:reports&max_age=5min"

  - match:
      prefix: "/"
    route:
      cluster: app_backend
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        check_settings:
          http_service:
            path_override: "/auth/api/forward?perm=myapp:login"
```

See [perm argument](../api/perm.md) and [max_age argument](../api/max-age.md) for query parameter syntax.

## WebSocket support for `/auth/`

If you use a dedicated authentication host (`--auth-host`), route `auth.example.com` to the Paskia cluster and you do not need the `/auth/` bypass above. Otherwise, make sure the `/auth/` route keeps the `Upgrade` and `Connection` headers so passkey WebSocket endpoints work. The default Envoy router handles `Upgrade` headers when the client requests them.

## Notes

- Envoy's `ext_authz` filter does not send the request body to the auth server by default. For Paskia this is fine.
- If Paskia is running behind TLS, use `https://` in `server_uri.uri` and configure the cluster's transport socket.
- The `failure_mode_allow: false` setting means that if Paskia cannot be reached, Envoy will reject the request. In testing you may prefer `true`, but use `false` in production so a failed auth service cannot accidentally allow traffic.
