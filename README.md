# Paskia

![Screenshot](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/forbidden-light.webp)

An easy to install passkey-based authentication service that protects any web application with strong passwordless login.

## What is Paskia?

- Easy to use fully featured auth&auth system (login and permissions)
- Organization and role-based access control (optional)
   * Org admins control their users and roles
   * Master admin can create multiple independent orgs
   * Master admin makes permissions available for orgs to assign
- User Profile and Administration by API and web interface.
under `/auth/` or `auth.example.com`
- Reset tokens and additional device linking via QR code or codewords.
- Pure Python, FastAPI, packaged with prebuilt Vue frontend

Two interfaces:
- API fetch: auth checks and login without leaving your app
- Forward-auth proxy: protect any unprotected site or service (Caddy, Nginx)

The API mode is useful for applications that can be customized to run with Paskia. Forward auth can also protect your javascript and other assets. Each provides fine-grained permission control and reauthentication requests where needed, and both can be mixed where needed.

Single Sign-On (SSO): Users register once and authenticate across all applications under your domain name (configured rp-id).

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

There is no config file. All settings are passed as CLI options:

```text
paskia [options]
paskia reset [user]     # Generate passkey reset link
```

| Option | Description | Default |
|--------|-------------|---------|
| -l, --listen *endpoint* | Listen address: *host*:*port*, :*port* (all interfaces), or */path.sock* | **localhost:4401** |
| --rp-id *domain* | Main/top domain for passkeys | **localhost** |
| --rp-name *"text"* | Name shown during passkey registration | Same as rp-id |
| --origin *url* | Restrict allowed origins for WebSocket auth (repeatable) | All under rp-id |
| --auth-host *url* | Dedicated authentication site, e.g. **auth.example.com** | Use **/auth/** path on each site |

## Further Documentation

- [Caddy configuration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Caddy.md)
- [Trusted Headers for Backend Apps](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Headers.md)
- [Frontend integration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Integration.md)
- [Paskia API](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/API.md)
