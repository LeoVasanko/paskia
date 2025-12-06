# Paskia E2E Tests

End-to-end tests for Paskia using [Playwright](https://playwright.dev/) with Chrome's **Virtual Authenticator**.

## Overview

These tests exercise the complete WebAuthn/passkey authentication flow without requiring physical hardware. Chrome's DevTools Protocol provides a virtual authenticator that can:

- Generate passkey credentials
- Sign authentication challenges
- Store resident keys (discoverable credentials)
- Simulate user verification (biometrics/PIN)

## Prerequisites

- Node.js 18+
- Python with `uv` (for running the backend server)

## Setup

```bash
cd e2e
npm install
npm run install:browsers
```

## Running Tests

### Basic Test Run

```bash
npm test
```

This will:
1. Start a fresh Paskia server with a test database
2. Run all E2E tests against it
3. Clean up the server when done

### With Coverage

```bash
npm run test:coverage
```

Runs tests and collects coverage for both:
- **Python backend** (via `coverage.py`) - HTML report in `coverage-html/`
- **Frontend JavaScript** (via Chrome V8 coverage) - JSON data in `e2e/coverage-frontend/`

### Interactive Mode

```bash
npm run test:ui
```

Opens Playwright's UI mode for interactive test debugging.

### Headed Mode

```bash
npm run test:headed
```

Runs tests with a visible browser window.

### Debug Mode

```bash
npm run test:debug
```

Runs tests with Playwright Inspector for step-by-step debugging.

## Test Structure

```
e2e/
├── playwright.config.ts      # Playwright configuration
├── package.json
├── tsconfig.json
├── test-data/                # Test database (created at runtime)
│   └── test.sqlite
└── tests/
    ├── global-setup.ts       # Creates fresh DB, captures reset token
    ├── global-teardown.ts    # Cleanup
    ├── passkey.spec.ts       # Main E2E tests
    └── fixtures/
        ├── virtual-authenticator.ts  # Virtual authenticator setup
        └── passkey-helpers.ts        # WebSocket helpers
```

## What's Tested

### Registration Flow
- Bootstrap admin user registration via reset token
- WebSocket challenge-response with virtual authenticator
- Session token creation and validation

### Authentication Flow
- Passkey authentication via WebSocket
- Credential verification
- Session management

### Session Management
- Token validation (`/auth/api/validate`)
- User info retrieval (`/auth/api/user-info`)
- Logout (`/auth/api/logout`)
- Invalid/missing token rejection

## How Virtual Authenticator Works

The tests use Chrome DevTools Protocol (CDP) to create a virtual authenticator:

```typescript
const cdpSession = await page.context().newCDPSession(page)
await cdpSession.send('WebAuthn.enable')
await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
})
```

This creates an in-browser authenticator that:
- Automatically responds to WebAuthn prompts
- Stores credentials persistently during the test session
- Simulates user verification without actual biometric input

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_URL` | Server URL | `http://localhost:4401` |
| `CI` | CI environment flag | - |
| `CLEANUP_TEST_DB` | Remove test DB after run | `false` |

## Limitations

1. **Chromium only**: Virtual authenticator is a Chrome DevTools feature
2. **No cross-origin**: Tests run on localhost; production-like origins need additional setup
3. **Single user per run**: Bootstrap creates one admin user; additional users need admin API

## Debugging Tips

1. **Check test database**: `e2e/test-data/test.sqlite` persists after tests
2. **View server output**: Global setup echoes server bootstrap to console
3. **Use trace viewer**: `npx playwright show-trace` on failure traces

## CI Integration

The tests are designed for CI environments:

```yaml
- name: Run E2E Tests
  run: |
    cd e2e
    npm ci
    npm run install:browsers
    npm test
  env:
    CI: true
```
