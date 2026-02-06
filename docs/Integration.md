# Integrating Paskia with your App

This guide covers frontend and backend integration with Paskia. For Caddy forward-auth setup, see [Caddy configuration](Caddy.md).

## Frontend Integration

### Using the paskia-js Module

The [paskia](https://www.npmjs.com/package/paskia) JavaScript module provides utilities for API calls, session validation, and authentication overlays. Works with any framework or vanilla JS.

```html
<script type="module">
  import { apiJson, apiFetch, SessionValidator } from 'https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js'
</script>
```

Or install to your project:

```sh
npm install paskia
```

### API Fetch with Automatic Auth

Use `apiJson` or `apiFetch` for API calls. When a 401/403 response includes an auth URL, the authentication dialog appears automatically, then the request retries. The JSON variant is purely for convenience, doing JSON headers and conversions for you.

```js
import { apiJson, apiFetch, AuthCancelledError } from 'paskia'

// JSON API call (sets Content-Type, parses response)
try {
  const data = await apiJson('/api/endpoint', { method: 'POST', body: { key: 'value' } })
} catch (e) {
  if (e instanceof AuthCancelledError) {
    // User cancelled auth dialog
  }
}

// Raw fetch with auth handling (returns Response object)
const response = await apiFetch('/api/endpoint')
```

For requests that shouldn't trigger auth dialogs, use standard `fetch` or our `fetchJson`.

### Session Validation Polling

Keep sessions alive and detect when the user logs out or switches accounts:

```js
import { SessionValidator } from 'paskia'

const validator = new SessionValidator(
  () => currentUser?.uuid,              // getter for current user ID
  (error) => handleSessionLost(error)   // callback when session is lost or user changes
)

validator.start()  // start polling (pauses on idle)
validator.stop()   // stop polling
```

The validator calls `/auth/api/validate` periodically to:
- Renew the session cookie (24h lifetime)
- Detect if the user logged out or switched accounts
- Pause polling when the page is idle, allowing sessions to expire when not used

### Manual Auth Flow

If you need custom control, handle 401/403 responses manually:

```js
import { showAuthIframe, AuthCancelledError } from 'paskia'

const response = await fetch('/api/protected')
if (response.status === 401 || response.status === 403) {
  const data = await response.json()
  if (data.auth?.iframe) {
    try {
      await showAuthIframe(data.auth.iframe)
      // Retry the original request
    } catch (e) {
      if (e instanceof AuthCancelledError) {
        // User clicked Back
      }
    }
  }
}
```

### User Info and Profile

Get current user details:

```js
const user = await apiJson('/auth/api/user-info', { method: 'POST' })
// Returns: { uuid, display_name, credentials, sessions, permissions, ... }
```

Or link to the built-in profile page: `/auth/`

## Backend Integration

### Using Forward-Auth Headers

When using Caddy forward-auth, your backend receives `Remote-*` headers on authenticated requests. See [Headers](Headers.md) for the full list.

```python
# Example: Python/FastAPI
@app.get("/api/data")
def get_data(request: Request):
    user_id = request.headers.get("Remote-User")
    org_id = request.headers.get("Remote-Org")
    permissions = request.headers.get("Remote-Groups", "").split(",")
    # ...
```

### Direct Validation from Backend

Your backend can validate sessions directly by calling Paskia's validate endpoint:

```python
import httpx

async def validate_session(request) -> dict:
    """Validate a session cookie and check permissions."""
    authcookie = request.get("__Host-paskia")
    response = await httpx.post(
        "http://localhost:4401/auth/api/validate?perm=myapp:login+myapp:api",
        headers={
            "Host": request.headers["host"]
            "X-Forwarded-For": request.client.host,
            "Cookie": f"__Host-paskia={}",
        },
    )
    if response.status_code != 200:
        return response.json()  # Return to client
    # User authenticated... We are good to go!
    ctx = response.json()  # User and session information
```

This is useful for:
- WebSocket connections where headers aren't available after handshake
- Background jobs that need to verify a stored session
- APIs not behind forward-auth (auth/restrict)

### Validate Endpoint Parameters

`POST /auth/api/validate` accepts query parameters:

| Parameter | Description |
|-----------|-------------|
| `perm=scope:name` | Require this permission (repeatable) |
| `max_age=5min` | Require recent passkey use |

Returns 200 with user info on success, 401/403 on failure.

## Proxying /auth/ to Paskia

Your app server needs to proxy `/auth/` paths to Paskia. This can be done by your application but is much easier done by Caddy or Nginx.

### Caddy

This handles both HTTP and WebSocket connections. Caddy's `reverse_proxy` handles HTTP and WebSocket transparently. This is essentially what our Caddy [auth/setup](../caddy/auth/setup) snippet does: `reverse_proxy :4401`.

```caddyfile
app.example.com {
    import auth/setup
    # ... your routes in handle blocks
}
```

### Nginx

Certain headers need to be configured for correct host and WS support:

```nginx
location /auth/ {
    proxy_pass http://localhost:4401;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

### Node.js / Express

Using `http-proxy-middleware`:

```js
import { createProxyMiddleware } from 'http-proxy-middleware'

app.use('/auth', createProxyMiddleware({ target: 'http://localhost:4401', ws: true, changeOrigin: false }))
```

### Python / FastAPI

You will need to process and handle `/auth/` for HTTP requests and `/auth/ws/` for WebSockets manually, which is beyond the scope of this documentation.

We highly recommend Caddy instead as the simpler and more production-worthy solution that Just Works.
