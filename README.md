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

## Requirements

- Python 3.9+
- A WebAuthn-compatible authenticator (security key, biometric device, etc.)

## Quick Start

### Using uv (recommended)

```fish
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone/navigate to the project directory
cd passkeyauth

# Install dependencies and run
uv run passkeyauth.main:main
```

### Using pip

```fish
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate.fish  # or venv/bin/activate for bash

# Install the package in development mode
pip install -e ".[dev]"

# Run the server
python -m passkeyauth.main
```

### Using hatch

```fish
# Install hatch if you haven't already
pip install hatch

# Run the development server
hatch run python -m passkeyauth.main
```

## Usage

1. Start the server using one of the methods above
2. Open your browser to `http://localhost:8000`
3. Enter a username (or use the default)
4. Click "Register Passkey"
5. Follow your authenticator's prompts to create a passkey

The WebSocket connection will show real-time status updates as you progress through the registration flow.

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
