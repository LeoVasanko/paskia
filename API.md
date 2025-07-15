# PassKey Auth API Documentation

This document describes all API endpoints available in the PassKey Auth FastAPI application.

## Base URL
- **Development**: `http://localhost:4401`
- All API endpoints are prefixed with `/auth`

## Authentication
The API uses JWT tokens stored in HTTP-only cookies for session management. Some endpoints require authentication via session cookies.

---

## HTTP API Endpoints

### User Management

#### `POST /auth/user-info`
Get detailed information about the current authenticated user and their credentials.

**Authentication**: Required (session cookie)

**Response**:
```json
{
  "status": "success",
  "user": {
    "user_id": "string (UUID)",
    "user_name": "string",
    "created_at": "string (ISO 8601)",
    "last_seen": "string (ISO 8601)",
    "visits": "number"
  },
  "credentials": [
    {
      "credential_id": "string (hex)",
      "aaguid": "string (UUID)",
      "created_at": "string (ISO 8601)",
      "last_used": "string (ISO 8601) | null",
      "last_verified": "string (ISO 8601) | null",
      "sign_count": "number",
      "is_current_session": "boolean"
    }
  ],
  "aaguid_info": "object (AAGUID information)"
}
```

**Error Response**:
```json
{
  "error": "Not authenticated" | "Failed to get user info: <error_message>"
}
```

---

### Session Management

#### `POST /auth/logout`
Log out the current user by clearing the session cookie.

**Authentication**: Not required

**Response**:
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

#### `POST /auth/set-session`
Set session cookie using JWT token from request body or Authorization header.

**Authentication**: Not required

**Request Body** (alternative to Authorization header):
```json
{
  "token": "string (JWT token)"
}
```

**Headers** (alternative to request body):
```
Authorization: Bearer <JWT_token>
```

**Response**:
```json
{
  "status": "success",
  "message": "Session cookie set successfully",
  "user_id": "string (UUID)"
}
```

**Error Response**:
```json
{
  "error": "No session token provided" | "Invalid or expired session token" | "Failed to set session: <error_message>"
}
```

#### `GET /auth/forward-auth`
Verification endpoint for use with Caddy forward_auth or Nginx auth_request.

**Authentication**: Required (session cookie)

**Success Response**:
- Status: `204 No Content`
- Headers: `x-auth-user-id: <user_id>`

**Error Response**:
- Status: `401 Unauthorized`
- Returns authentication app HTML page
- Headers: `www-authenticate: PrivateToken`

---

### Credential Management

#### `POST /auth/delete-credential`
Delete a specific passkey credential for the current user.

**Authentication**: Required (session cookie)

**Request Body**:
```json
{
  "credential_id": "string (hex-encoded credential ID)"
}
```

**Response**:
```json
{
  "status": "success",
  "message": "Credential deleted successfully"
}
```

**Error Response**:
```json
{
  "error": "Not authenticated" | "credential_id is required" | "Invalid credential_id format" | "Credential not found or access denied" | "Cannot delete current session credential" | "Cannot delete last remaining credential" | "Failed to delete credential: <error_message>"
}
```

---

### Device Addition

#### `POST /auth/create-device-link`
Generate a device addition link for authenticated users to add new passkeys to their account.

**Authentication**: Required (session cookie)

**Response**:
```json
{
  "status": "success",
  "message": "Device addition link generated successfully",
  "addition_link": "string (URL)",
  "expires_in_hours": 24
}
```

**Error Response**:
```json
{
  "error": "Authentication required" | "Failed to create device addition link: <error_message>"
}
```

#### `POST /auth/validate-device-token`
Validate a device addition token and return associated user information.

**Authentication**: Not required

**Request Body**:
```json
{
  "token": "string (device addition token)"
}
```

**Response**:
```json
{
  "status": "success",
  "valid": true,
  "user_id": "string (UUID)",
  "user_name": "string",
  "token": "string (device addition token)"
}
```

**Error Response**:
```json
{
  "error": "Device addition token is required" | "Invalid or expired device addition token" | "Device addition token has expired" | "Failed to validate device addition token: <error_message>"
}
```

---

### Static File Serving

#### `GET /auth/{passphrase}`
Handle passphrase-based authentication redirect with cookie setting.

**Parameters**:
- `passphrase`: String matching pattern `^\w+(\.\w+){2,}$` (e.g., "word1.word2.word3")

**Response**:
- Status: `303 See Other`
- Redirect to: `/`
- Sets temporary cookie: `auth-token` (expires in 2 seconds)

#### `GET /auth`
Serve the main authentication app.

**Response**: Returns the main `index.html` file for the authentication SPA.

#### `GET /auth/assets/{path}`
Serve static assets (CSS, JS, images) for the authentication app.

#### `GET /{path:path}`
Catch-all route for SPA routing. Serves `index.html` for all non-API routes when requesting HTML content.

**Response**:
- For HTML requests: Returns `index.html`
- For non-HTML requests: Returns `404 Not Found` JSON response

---

## WebSocket API Endpoints

All WebSocket endpoints are mounted under `/auth/ws/`.

### Registration

#### `WS /auth/ws/register_new`
Register a new user with a new passkey credential.

**Flow**:
1. Client connects to WebSocket
2. Server sends registration options
3. Client performs WebAuthn ceremony and sends response
4. Server validates and creates new user + credential
5. Server sends JWT token for session establishment

**Server Messages**:
```json
// Registration options
{
  "rp": { "id": "localhost", "name": "Passkey Auth" },
  "user": { "id": "base64", "name": "string", "displayName": "string" },
  "challenge": "base64",
  "pubKeyCredParams": [...],
  "timeout": 60000,
  "attestation": "none",
  "authenticatorSelection": {...}
}

// Success response
{
  "status": "success",
  "message": "User registered successfully",
  "token": "string (JWT)"
}

// Error response
{
  "status": "error",
  "message": "error description"
}
```

#### `WS /auth/ws/add_credential`
Add a new passkey credential to an existing authenticated user.

**Authentication**: Required (session cookie)

**Flow**:
1. Client connects with valid session
2. Server sends registration options for existing user
3. Client performs WebAuthn ceremony and sends response
4. Server validates and adds new credential
5. Server sends success confirmation

#### `WS /auth/ws/add_device_credential`
Add a new passkey credential using a device addition token.

**Flow**:
1. Client connects and sends device addition token
2. Server validates token and sends registration options
3. Client performs WebAuthn ceremony and sends response
4. Server validates, adds credential, and cleans up token
5. Server sends JWT token for session establishment

**Initial Client Message**:
```json
{
  "token": "string (device addition token)"
}
```

### Authentication

#### `WS /auth/ws/authenticate`
Authenticate using existing passkey credentials.

**Flow**:
1. Client connects to WebSocket
2. Server sends authentication options
3. Client performs WebAuthn ceremony and sends response
4. Server validates credential and updates usage stats
5. Server sends JWT token for session establishment

**Server Messages**:
```json
// Authentication options
{
  "challenge": "base64",
  "timeout": 60000,
  "rpId": "localhost",
  "allowCredentials": [...] // Optional, for non-discoverable credentials
}

// Success response
{
  "status": "success",
  "message": "Authentication successful",
  "token": "string (JWT)"
}

// Error response
{
  "status": "error",
  "message": "error description"
}
```

---

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "string (error description)"
}
```

## Security Features

- **HTTP-only Cookies**: Session tokens are stored in secure, HTTP-only cookies
- **CSRF Protection**: SameSite cookie attributes prevent CSRF attacks
- **Token Validation**: All JWT tokens are validated and automatically refreshed
- **Credential Isolation**: Users can only access and modify their own credentials
- **Time-based Expiration**: Device addition tokens expire after 24 hours
- **Rate Limiting**: WebSocket connections are limited and validated

## CORS and Headers

The application includes appropriate CORS headers and security headers for production use with reverse proxies like Caddy or Nginx.
