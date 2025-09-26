## Caddy configuration

We provide a few Caddy snippets that make the configuration easier, although the `forward_auth` directive of Caddy can be used directly as well. Place the auth folder with the snippets where your Caddyfile is.

What these snippets do
- Mount the auth UI at `/auth/` proxying to `:4401` (auth backend)
- Use the forward-auth interface `/auth/api/forward` to verify the required credentials
- Render a login page or a permission denied page if needed (without changing URL)

### 1) Your site has no auth yet — protect the whole thing

Use this when you want “login required everywhere” which is useful to protect some service that doesn't have any authentication of its own:

```caddyfile
localhost {
    import auth/all "" {
        reverse_proxy :3000  # your app
    }
}
```

The auth/all protects the entire site with a simple directive. Put your normal setup inside the block. In this example we don't require any permissions, only that the user is logged in. Instead of `""` you may specify `perm=myapp:login` or other permissions.

### 2) Different areas, different permissions

When you need a more fine-grained control, use the auth/setup and auth/require snippets:

```caddyfile
localhost {
    import auth/setup

    @public path /.well-known/* /favicon.ico
    handle @public {
        root * /var/www/
        file_server
    }

    @reports path /reports
    handle @reports {
        import auth/require perm=myapp:reports
        reverse_proxy :3000
    }

    # Anywhere else, require login only
    handle {
        import auth/require ""
        reverse_proxy :3000
    }
}
```

Note: We use the `handle @name` approach rather than `handle_path` to prevent the matched path being removed out of upstream URL. Unlike bare directives, these blocks will be tried in sequence and each can contain what you'd typically put in your site definition.

---

## Override the auth backend URL (AUTH_UPSTREAM)

By default, the auth service is contacted at localhost port 4401 ("for authentication required"). You can point Caddy to a different by setting the `AUTH_UPSTREAM` environment variable for Caddy.

If unset, the snippets use `:4401` by default.

## Headers your app receives

When a request is allowed, the auth service adds these headers before proxying to your app (e.g., the service at `:3000`). Your app can use them for user context and authorization.

| Header | Meaning | Example |
|---|---|---|
| `Remote-User` | Authenticated user UUID | `3f1a2b3c-4d5e-6789-abcd-ef0123456789` |
| `Remote-Name` | User display name | `Jane Doe` |
| `Remote-Org` | Organization UUID | `a1b2c3d4-1111-2222-3333-444455556666` |
| `Remote-Org-Name` | Organization display name | `Acme Inc` |
| `Remote-Role` | Role UUID | `b2c3d4e5-2222-3333-4444-555566667777` |
| `Remote-Role-Name` | Role display name | `Administrators` |
| `Remote-Groups` | Comma‑separated permissions the user has | `myapp:reports,auth:admin` |
| `Remote-Session-Expires` | Session expiry timestamp (ISO 8601) | `2025-09-25T14:30:00Z` |
| `Remote-Credential` | Credential UUID backing the session | `c3d4e5f6-3333-4444-5555-666677778888` |

Note: Incoming `Remote-*` headers from clients are stripped by `auth/setup` or `auth/all`, so apps can trust these values.
