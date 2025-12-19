# Paskia Caddy Configuration

[Caddy](https://caddyserver.com/) is a modern web server that makes setting up web services easy. We provide a few Caddy snippets that make the configuration even easier, although the `forward_auth` directive of Caddy can be used directly as well. Place the [auth folder](../caddy/auth) with the snippets `require` and `setup` where your config file is (e.g. `/etc/caddy/auth`)

What these snippets do
- `setup`: Mount the auth UI at `/auth/` proxying to `:4401`
- `require`: Use `/auth/api/forward` for access control
- Render a login page or a permission denied page if needed (without changing URL)

Your backend may not use authentication at all, or it can make use of the user information passed via `Remote-*` headers by the authentication system, see [trusted headers](Headers.md) for details.

We assume the normal unprotected **Caddyfile** for your site looks like this:

```caddyfile
app.example.com {
    @public path /.well-known/* /favicon.ico
    handle @public {
        root * /var/www/
        file_server
    }

    handle {
        reverse_proxy :3000  # Your app backend
    }
}
```

Note: We use the `handle @name` approach rather than `handle_path` to keep the path unaltered. Unlike bare directives, these blocks will be tried in sequence and each can contain what you'd typically put in your site definition (by default `reverse_proxy` takes precedence and nothing reaches the static files).

We will adapt from this to protect your app.

### Protect your site (auth/setup, auth/require)

```caddyfile
app.example.com {
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

    handle {
        import auth/require max-age=12h
        reverse_proxy :3000
    }
}
```

The above setup allows unauthenticated access to certain files, then implements two different access controls for your backend app depending on which path is accessed. Note that the perm and max-age options may be combined, e.g. ``perm=myapp:admin&max-age=5min` on a very sensitive endpoint. This will require additional authentication if the passkey hasn't been used in the last 5 minutes (automatic session renewals don't affect this). Use `""` if you only want the user to be authenticated with no time or perm requirements.

### Dedicated Authentication Site

When you setup a separate subdomain for the authentication site, just add to your config another section for the auth host:

```
auth.example.com {
    reverse_proxy :4401
}
```

Remember to specify `paskia serve --auth-host auth.example.com` to restrict the authentication services to this domain.

Note that we still reserve `/auth/` on each site for logout page and any APIs your application may require, while full user profile and global options are only available on the auth host.

Paskia does not require CORS configuration, but it can access the authentication and registration of auth host WS API from the other sites as WebSockets don't require any CORS.

### Override the paskia backend address (AUTH_UPSTREAM)

By default, the auth service is contacted at localhost port 4401. You can point Caddy to a different address by setting the `AUTH_UPSTREAM` environment variable for Caddy.

If unset, the snippets use `:4401` by default.
