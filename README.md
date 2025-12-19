# Paskia

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
uvx paskia serve --rp-id example.com
```

On the first run it downloads the software and prints a registration link for the Admin. If you are going to be connecting `localhost` directly, for testing, leave out the rp-id.

The server will start up on [localhost:4401](http://localhost:4401) *for authentication required*, serving for `*.example.com`.

Otherwise you will need a web server such as [Caddy](https://caddyserver.com/) to serve HTTPS on your actual domain names and proxy requests to Paskia and your backend apps (see documentation below).

For a permanent install of `paskia` CLI command, not needing `uvx`:

```fish
uv tool install paskia
```

## Configuration

There is no config file. Pass only the options on CLI:

```text
paskia serve [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| Listen address | One of **<host>:<port>** (default all hosts, port 4401) or **unix:/path/to/paskia.socket** (Unix socket) | **localhost:4401** |
| --rp-id **<domain>** | Main/top domain | **localhost** |
| --rp-name **<text>** | Name of your company or site | Same as rp-id |
| --origin **url>** | Explicitly list the domain names served () | **https://rp-id** |
| --auth-host **<domain>** | Dedicated authentication site (e.g., **auth.example.com**) | Unspecified: we use **/auth/** on *every* site under rp-id.|

## Further Documentation

- [Caddy configuration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Caddy.md)
- [Trusted Headers for Backend Apps](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Headers.md)
- [Frontend integration](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/Integration.md)
- [Paskia API](https://git.zi.fi/LeoVasanko/paskia/src/branch/main/docs/API.md)
