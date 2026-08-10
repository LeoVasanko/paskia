# Nginx Forward-Auth

[`/auth/api/forward`](../api/forward.md) · [Proxy guides](index.md)

This guide uses the [Nginx `auth_request`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module to ask Paskia whether each request is allowed before proxying it to your backend.

## Overview

```nginx
server {
    listen 80;
    server_name app.example.com;

    # 1. Proxy /auth/ to Paskia (HTTP + WebSocket).
    location /auth/ {
        proxy_pass http://localhost:4401;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }

    # 2. All other paths are protected.
    location / {
        auth_request /auth-internal;

        # 3. Capture the Remote-* headers from the auth response and
        #    pass them to the backend request.
        auth_request_set $remote_user        $upstream_http_remote_user;
        auth_request_set $remote_name        $upstream_http_remote_name;
        auth_request_set $remote_groups      $upstream_http_remote_groups;
        auth_request_set $remote_org         $upstream_http_remote_org;
        auth_request_set $remote_org_name    $upstream_http_remote_org_name;
        auth_request_set $remote_role        $upstream_http_remote_role;
        auth_request_set $remote_role_name   $upstream_http_remote_role_name;
        auth_request_set $remote_session_exp $upstream_http_remote_session_expires;
        auth_request_set $remote_credential  $upstream_http_remote_credential;

        proxy_set_header Remote-User             $remote_user;
        proxy_set_header Remote-Name             $remote_name;
        proxy_set_header Remote-Groups           $remote_groups;
        proxy_set_header Remote-Org              $remote_org;
        proxy_set_header Remote-Org-Name         $remote_org_name;
        proxy_set_header Remote-Role             $remote_role;
        proxy_set_header Remote-Role-Name        $remote_role_name;
        proxy_set_header Remote-Session-Expires  $remote_session_exp;
        proxy_set_header Remote-Credential       $remote_credential;

        # 4. The proxy_set_header lines above override any client-supplied
        #    Remote-* headers, so the backend receives only the values from
        #    Paskia's auth response.

        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # 5. Internal endpoint used by auth_request.
    location = /auth-internal {
        internal;
        proxy_pass http://localhost:4401/auth/api/forward?perm=myapp:login;
        proxy_http_version 1.1;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header Host $host;
        proxy_set_header Cookie $http_cookie;
        proxy_set_header Accept $http_accept;
        # Drop hop-by-hop headers that must not reach the auth subrequest.
        proxy_set_header Connection "";
        proxy_set_header Upgrade "";
        proxy_set_header Transfer-Encoding "";
        proxy_set_header Keep-Alive "";
        proxy_set_header Proxy-Connection "";
        proxy_set_header TE "";
    }
}

# WebSocket upgrade map.
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

## What the configuration does

1. **`/auth/`** is proxied straight to Paskia. The `Upgrade` and `Connection` headers are passed through so WebSocket endpoints such as `/auth/ws/authenticate` work.
2. **`/`** is protected by `auth_request /auth-internal`. Nginx makes an internal subrequest to that location before proxying the original request to the app.
3. **`auth_request_set`** captures each `Remote-*` header from the Paskia response. Nginx does not have wildcard capture, so every header must be listed explicitly. The captured values are then attached to the backend request with `proxy_set_header`.
4. The `proxy_set_header` lines override any `Remote-*` headers the client might have sent, so the backend can trust the headers that come from Paskia.
5. **`/auth-internal`** is the actual forward-auth call. It must:
   - point to `/auth/api/forward`,
   - not forward the request body (`proxy_pass_request_body off;`),
   - pass `Host`, `Cookie`, `Accept`, `X-Forwarded-Method`, and `X-Forwarded-Uri`,
   - strip hop-by-hop headers.

## Adjusting requirements

Change the query string on the `proxy_pass` line inside `/auth-internal` to require different permissions or recent authentication:

```nginx
proxy_pass http://localhost:4401/auth/api/forward?perm=myapp:login;
proxy_pass http://localhost:4401/auth/api/forward?perm=myapp:admin&max_age=5min;
proxy_pass http://localhost:4401/auth/api/forward?"";
```

The last form (`?""`) requires only authentication and no specific permission. See [perm argument](../api/perm.md) and [max_age argument](../api/max-age.md) for details.

## Public paths

To leave some paths unprotected (for example `/.well-known/` or `/static/`), add `location` blocks before the protected `location /` block:

```nginx
location /.well-known/ {
    root /var/www;
}

location /static/ {
    root /var/www;
}
```

## Notes

- Nginx `auth_request` always makes the auth subrequest with the same HTTP method as the original request, but the body is suppressed by the configuration above. Paskia uses the `X-Forwarded-Method` and `X-Forwarded-Uri` headers for logging.
- The `auth_request_set` variables are empty when the auth request fails, so on 401/403 the backend is never contacted; Nginx returns Paskia's response directly.
- For HTTPS, add `listen 443 ssl;` and your certificate configuration as usual.
