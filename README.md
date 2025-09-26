# PasskeyAuth

A minimal FastAPI WebAuthn server with WebSocket support for passkey registration. This project demonstrates WebAuthn registration flow with Resident Keys (discoverable credentials) using modern Python tooling.

## Features

- 🔐 WebAuthn registration with Resident Keys support
- 🔌 WebSocket-based communication for real-time interaction
- 🚀 Modern Python packaging with `pyproject.toml`
- 🎨 Clean, responsive HTML interface using @simplewebauthn/browser
- 📦 No database required - challenges stored locally per connection
- 🛠️ Development tools: `ruff` for linting and formatting
- 🧹 Clean architecture with local challenge management

## Docs

- Caddy integration: see `CADDY.md` for short, copy-paste snippets to secure your site with Caddy.

## Requirements

- Python 3.9+
- A WebAuthn-compatible authenticator (security key, biometric device, etc.)

## Quick Start

### Install (editable dev mode)

```fish
uv pip install -e .[dev]
```

### Run (new CLI)

`passkey-auth` now provides subcommands:

```text
passkey-auth serve [host:port] [--options]
passkey-auth dev   [--options]
```

Examples (fish shell shown):

```fish
# Production style (no reload)
passkey-auth serve
passkey-auth serve 0.0.0.0:8080 --rp-id example.com --origin https://example.com

# Development (auto-reload)
passkey-auth dev            # localhost:4401
passkey-auth dev :5500      # localhost on port 5500
passkey-auth dev 127.0.0.1  # host only, default port 4401
```

Available options (both subcommands):

```text
--rp-id <id>        Relying Party ID (default: localhost)
--rp-name <name>    Relying Party name (default: same as rp-id)
--origin <url>      Explicit origin (default: https://<rp-id>)
```

### Legacy Invocation

If you previously used `python -m passkey.fastapi --dev --host ...`, switch to the new form above. The old flags `--host`, `--port`, and `--dev` are replaced by the `[host:port]` positional and the `dev` subcommand.

## Usage (Web)

1. Start the server with one of the commands above
2. Open your browser to `http://localhost:4401/auth/` (or your chosen host/port)
3. Enter a username (or use the default)
4. Click "Register Passkey"
5. Follow your authenticator's prompts

Real-time status updates stream over WebSocket.

## Development

### Code Quality

```fish
# Run linting and formatting with ruff
uv run ruff check .
uv run ruff format .

# Or with hatch
hatch run ruff check .
hatch run ruff format .
```

### Project Structure

```
passkeyauth/
├── passkeyauth/
│   ├── __init__.py
│   └── main.py          # FastAPI server with WebSocket support
├── static/
│   └── index.html       # Frontend interface
├── pyproject.toml       # Modern Python packaging configuration
└── README.md
```

## Technical Details

### WebAuthn Configuration

- **Relying Party ID**: `localhost` (for development)
- **Resident Keys**: Required (enables discoverable credentials)
- **User Verification**: Preferred
- **Supported Algorithms**: ECDSA-SHA256, RSASSA-PKCS1-v1_5-SHA256

### WebSocket Message Flow

1. Client connects to `/ws/{client_id}`
2. Client sends `registration_challenge` message
3. Server responds with `registration_challenge_response`
4. Client completes WebAuthn ceremony and sends `registration_response`
5. Server verifies and responds with `registration_success` or `error`

### Security Notes

- This is a minimal demo - challenges are stored locally per WebSocket connection
- For production use, implement proper user storage and session management
- Consider using Redis or similar for challenge storage in production with multiple server instances
- Ensure HTTPS in production environments

## License

MIT License - feel free to use this as a starting point for your own WebAuthn implementations!
