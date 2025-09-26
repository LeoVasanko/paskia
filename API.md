# PassKey Auth API Documentation

This document describes all API endpoints available in the PassKey Auth FastAPI application, that by default listens on `localhost:4401` ("for authentication required").

### HTTP Endpoints

GET /auth/ - Main authentication app
GET /auth/admin/ - Admin app for managing organisations, users and permissions
GET /auth/{reset_token} - Process password reset/share token
POST /auth/api/user-info - Get authenticated user information
POST /auth/api/logout - Logout and delete session
POST /auth/api/set-session - Set session cookie from Authorization header
POST /auth/api/create-link - Create device addition link
DELETE /auth/api/credential/{uuid} - Delete specific credential
POST /auth/api/validate - Session validation and renewal endpoint (fetch regularly)
GET /auth/api/forward - Authentication validation for Caddy/Nginx
		- On success returns `204 No Content` with [user info](Headers.md)
		- Otherwise returns
		   * `401 Unauthorized` - authentication required
		   * `403 Forbidden` - missing required permissions
		   * Serves the authentication app for a login or permission denied page
		- Does not renew session!

### WebAuthn/Passkey endpoints (WebSockets)

WS /auth/ws/register - Register new user with passkey
WS /auth/ws/add_credential - Add new credential for existing user
WS /auth/ws/authenticate - Authenticate user with passkey
