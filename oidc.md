# OIDC Provider Implementation

OpenID Connect 1.0 provider enabling third-party apps to authenticate users via passkey. Also supports native cookie-based authentication.

## Data Models

**User** — Added: `email`, `preferred_username`

**Session** — Added: `client_uuid` (None = native, set = OIDC)
- `key: bytes` — hashed DB key, never stored raw
- `secret` → `hash_secret("session", secret)` → DB lookup
- OIDC `sid` → `base64url.encode(hash_secret("oidc", session.key))`

**OIDClient** — `uuid, client_secret_hash, name, redirect_uris`

## Auth Codes (In-Memory Only)

60-second lifetime, auto-cleaned:

```python
from paskia.authcode import AuthCode, OIDC, codes

class AuthCode(msgspec.Struct):
    session_key: str       # Session DB key
    created: datetime
    oidc: OIDC | None      # Only for OIDC mode

class OIDC(msgspec.Struct):
    redirect_uri, scope, nonce, code_challenge, code_challenge_method: str
```

Usage: `code = authcode.store(AuthCode(...))` → later `codes.pop(code, None)`

## Authorization Flows

### OIDC (Authorization Code)

1. `GET /auth/restricted/oidc?client_id=UUID&redirect_uri=...&scope=openid&nonce=...&code_challenge=...`
2. Frontend → WebSocket: `/auth/ws/authenticate?client_id=...&redirect_uri=...&...`
3. Validate client/redirect_uri, authenticate via passkey
4. `db.oidc_login()` → `(secret, session_key)`
5. Create `AuthCode(session_key, oidc=OIDC(...))` → code
6. Return: `{"redirect_url": "{redirect_uri}?code={code}&state={state}"}`
7. Client exchanges code at `/auth/oidc/token` with `code_verifier` (PKCE S256)

**Token:** `access_token, id_token, refresh_token={secret}, expires_in=3600`

**ID token:** `sub, sid (base64url), name, preferred_username, email, groups`

### Native (Cookie)

1. WebSocket: `/auth/ws/authenticate` (no OIDC params)
2. Authenticate via passkey
3. `db.login()` → secret
4. Create `AuthCode(session_key=secret, oidc=None)` → exchange_code
5. Return: `{"user": "UUID", "exchange_code": "..."}`
6. `POST /auth/api/exchange` with code → sets cookie

## Refresh & Logout

**Refresh:** `POST /auth/oidc/token` with `grant_type=refresh_token&refresh_token={secret}&client_id=...&client_secret=...`
- Looks up session, validates client match
- Extends expiry +24h (sliding window)
- Returns new tokens with same `sid`

**Back-channel logout:** `POST /auth/oidc/backchannel-logout` with `logout_token={jwt}`
- Verify signature, extract `sid` or `sub`
- Delete matched sessions
- Return 200 OK

Discovery: `backchannel_logout_supported: true`

## Endpoints

- `GET /.well-known/openid-configuration` — Discovery
- `GET /auth/oidc/keys` — Keys (EdDSA)
- `POST /auth/oidc/token` — Exchange/refresh
- `GET /auth/oidc/userinfo` — User (bearer token)
- `POST /auth/oidc/backchannel-logout` — Logout
- `POST /auth/api/exchange` — Native auth code → cookie

## Files

**Created:** [paskia/authcode.py](paskia/authcode.py), [paskia/util/crypto.py](paskia/util/crypto.py), [paskia/fastapi/oid.py](paskia/fastapi/oid.py)

**Modified:** [paskia/db/structs.py](paskia/db/structs.py), [paskia/db/operations.py](paskia/db/operations.py), [paskia/fastapi/ws.py](paskia/fastapi/ws.py), [paskia/fastapi/api.py](paskia/fastapi/api.py), [paskia/globals.py](paskia/globals.py), [paskia/fastapi/mainapp.py](paskia/fastapi/mainapp.py)
