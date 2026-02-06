# Paskia

![Login dialog screenshot](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/login-light.webp)

An easy to install passkey-based authentication service that protects any web application with strong passwordless login.

## What is Paskia?

- Easy to use fully featured auth&auth system (login and permissions)
- Organization and role-based access control
   * Org admins control their users and roles
   * Multiple independent orgs
   * Master admin can do everything or delegate to org admins
- User Profile and Admin by API and web interface
- Implements login/reauth/forbidden flows for you
- Single Sign-On (SSO): Users register once and authenticate across your services
- Remote autentication by entering random keywords from another device (like 2fa)
- No CORS, NodeJS or anything extra needed.

## Authenticate to get to your app, or in your app

- API fetch: auth checks and login without leaving your app
- Forward-auth proxy: protect any unprotected site or service (Caddy, Nginx)

The API mode is useful for applications that can be customized to run with Paskia. Forward auth can also protect your javascript and other assets. Each provides fine-grained permission control and reauthentication requests where needed, and both can be mixed where needed.

## Authentication flows already done

![Forbidden dialog, dark mode](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/forbidden-dark.webp)
**Automatic light/dark mode switching with overrides by user profile and protected app's theme.**

Paskia includes set of login, reauthentication and forbidden dialogs that it can use to perform the needed flows. We never leave the URL, no redirections, and if you make use of API mode, we won't even interrupt whatever your app was doing but retry the blocked API fetch after login like nothing happened.

## Quick Start

Install [UV](https://docs.astral.sh/uv/getting-started/installation/) and run:

```fish
uvx paskia --rp-id example.com
```

On the first run it downloads the software and prints a registration link for the Admin. The server starts on [localhost:4401](http://localhost:4401), serving authentication for `*.example.com`. For local testing, leave out `--rp-id`.

For production you need a web server such as [Caddy](https://caddyserver.com/) to serve HTTPS on your actual domain names and proxy requests to Paskia and your backend apps (see documentation below).

For a permanent install of `paskia` CLI command, not needing `uvx`:

```fish
uv tool install paskia
```

## Configuration

All configuration is passed by CLI arguments, of which there are just a few.

```text
paskia [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| -l, --listen *endpoint* | Listen address: *host*:*port*, :*port* (all interfaces), or */path.sock* | **localhost:4401** |
| --rp-id *domain* | Main/top domain for passkeys | **localhost** |
| --rp-name *"text"* | Name shown during passkey registration | Same as rp-id |
| --origin *url* | Restrict allowed origins for WebSocket auth (repeatable) | All under rp-id |
| --auth-host *url* | Dedicated authentication site, e.g. **auth.example.com** | Use **/auth/** path on each site |

## Tutorial: From Local Testing to Production

This section walks you through a complete example, from running Paskia locally to protecting a real site in production.

### Step 1: Local Testing

For development and testing, run Paskia without any arguments:

```fish
paskia
```

This starts the server on [localhost:4401](http://localhost:4401) with passkeys bound to `localhost`. On first run, Paskia prints a registration link for the Master Admin—click it to register your first passkey.

### Step 2: Production Configuration

For a real deployment, configure Paskia with your domain name (rp-id). This enables SSO setup for that domain and any subdomains.

```fish
paskia --rp-id example.com --rp-name "Example Corp"
```

This binds passkeys to `*.example.com`. The `--rp-name` is shown to users during passkey registration.

### Step 3: Set Up Caddy

Install [Caddy](https://caddyserver.com/) and copy the [auth folder](caddy/auth) to `/etc/caddy/auth`. Say your current unprotected Caddyfile looks like this:

```caddyfile
app.example.com {
    reverse_proxy :3000
}
```

Add Paskia full site protection:

```caddyfile
app.example.com {
    import auth/setup
    handle {
        import auth/require perm=myapp:login
        reverse_proxy :3000
    }
}
```

Run `systemctl reload caddy`. Now `app.example.com` requires the `myapp:login` permission. Try accessing it and you'll land on a login dialog.

### Step 4: Assign Permissions via Admin Panel

![Admin panel permissions](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/master-permissions.webp)

1. Go to `app.example.com/auth/admin/`
2. Create a permission, give it a name and scope `myapp:login`
3. Assign it to Organization
4. In that organization, assign it to the Administration role

Now you have granted yourself the new permission.

Permission scopes are text identifiers with colons as separators that we can use for permission checks. The `myapp:` prefix is a convention to namespace permissions per application—you but you can use other forms as you see fit (urlsafe characters, no spaces allowed).

### Step 5: Add API Authentication to Your App

Your backend already receives `Remote-*` headers from Caddy's forward-auth. For frontend API calls, we provide a [JS paskia module](https://www.npmjs.com/package/paskia):

```js
import { apiJson } from 'https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js'

const data = await apiJson('/api/sensitive', { method: 'POST' })
```

When a 401/403 occurs, the auth dialog appears automatically, and the request retries after authentication.

To protect the API path with a different permission, update your Caddyfile:

```caddyfile
app.example.com {
    import auth/setup

    @api path /api/*
    handle @api {
        import auth/require perm=myapp:api
        reverse_proxy :3000
    }

    handle {
        import auth/require perm=myapp:login
        reverse_proxy :3000
    }
}
```

Create the `myapp:api` permission in the admin panel, that will be required for all API access. Link to `/auth/` for the built-in profile page.

You may also remove the `myapp:login` protection from the rest of your site paths, unless you wish to keep all your assets behind a login page. Having this as the last entry in your config allows free access to everything not matched by other sections.

```Caddyfile
    handle {
        reverse_proxy :3000
    }
```

### Step 6: Run Paskia as a Service

```fish
sudo systemctl edit --force --full paskia.service
```

Paste the following and save:

```ini
[Unit]
Description=Paskia Authentication Server

[Service]
Type=simple
WorkingDirectory=/var/lib/paskia
ExecStart=uvx paskia --rp-id example.com --rp-name "Example Corp"
DynamicUser=yes
StateDirectory=paskia

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```fish
sudo systemctl enable --now paskia
```

The database is stored in `/var/lib/paskia/paskia.jsonl`. You will have to install UV on your system level to make use of uvx and automatic updates on service restarts.


## Further Documentation

- [Caddy configuration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Caddy.md)
- [Trusted Headers for Backend Apps](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Headers.md)
- [Frontend integration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Integration.md)
- [Paskia API](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/API.md)
