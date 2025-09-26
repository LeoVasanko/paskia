# PassKey Auth API Documentation

This document describes all API endpoints available in the PassKey Auth FastAPI application.

## Base URL
- **Development**: `http://localhost:4401`
- All endpoints are prefixed with `/auth/`

### HTTP Endpoints
GET /auth/ - Main authentication app
GET /auth/api/forward - Authentication validation for Caddy/Nginx (was /auth/forward-auth)
		- On success returns `204 No Content` with the following headers:
			- `Remote-User`: authenticated user UUID
			- `Remote-Name`: display name
			- `Remote-Groups`: comma-separated permission IDs (no spaces)
			- `Remote-Org`: organization UUID
			- `Remote-Org-Name`: organization display name
			- `Remote-Role`: role UUID
			- `Remote-Role-Name`: role display name
			- `Remote-Session-Expires`: session expiry timestamp (ISO 8601)
			- `Remote-Credential`: credential UUID backing the session
POST /auth/validate - Token validation endpoint
POST /auth/user-info - Get authenticated user information
POST /auth/logout - Logout current user
POST /auth/set-session - Set session cookie from Authorization header
DELETE /auth/credential/{uuid} - Delete specific credential
POST /auth/create-link - Create device addition link
GET /auth/{reset_token} - Process reset token and redirect

### WebSocket Endpoints
WS /auth/ws/register - Register new user with passkey
WS /auth/ws/add_credential - Add new credential for existing user
WS /auth/ws/authenticate - Authenticate user with passkey
