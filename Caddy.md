## Caddy configuration

We provide a few Caddy snippets that make the configuration easier, although the `forward_auth` directive of Caddy can be used directly as well. Place the auth folder with the snippets where your Caddyfile is.

What these snippets do
- Mount the auth UI at `/auth/` proxying to `:4401` (auth backend)
- Use the forward-auth interface `/auth/api/forward` to verify the required credentials
- Render a login page or a permission denied page if needed (without changing URL)

Your backend may not use authentication at all, or it can make use of the user information passed via `Remote-*` headers by the authentication system, see [Headers.md](Headers.md) for details.

### 1) Protect the full site (auth/all)

Use this when you want “login required everywhere” which is useful to protect some service that doesn't have any authentication of its own:

```caddyfile
localhost {
    import auth/all "" {
        reverse_proxy :3000  # your app
    }
}
```

The auth/all protects the entire site with a simple directive. Put your normal setup inside the block. In this example we don't require any permissions, only that the user is logged in. Instead of `""` you may specify `perm=myapp:login` or other permissions.

It is possible to add your own `handle @matcher` blocks prior importing `auth/all` for endpoints that don't require authentication, e.g. to exclude `/favicon.ico`.

### 2) Different areas, different permissions (auth/setup, auth/require)

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
