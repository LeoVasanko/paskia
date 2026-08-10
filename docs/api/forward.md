# GET /auth/api/forward

[API overview](../API.md) · [Proxy guides](../proxy/index.md)

Forward-auth validation for reverse proxies. The proxy calls this endpoint for every incoming request; Paskia validates the session and either authorizes the request by returning 204 with `Remote-*` headers, or rejects it with 401/403 error responses with an HTML login page if `text/html` was requested (i.e. it's a browser viewing the page), or otherwise JSON with details on the error and a URL to initiate API authentication flow.

The proxy server follows the 204 response with the original request to protected service, adding those remote headers to original user request, sent to the service. Any error response is sent directly back to client, never connecting to the protected service.

See [Forward-Auth Proxy Guides](../proxy/index.md) for Caddy, Nginx, Traefik, Apache APISIX, Envoy and HAProxy configuration examples. Caddy users can also start from the dedicated [Caddy configuration guide](../proxy/caddy.md).


## Query parameters

| Parameter | Description |
|-----------|-------------|
| perm | Required permissions. See the [perm argument](perm.md). |
| max_age | Require recent passkey use. See the [max_age argument](max-age.md). |

## Request headers

| Header | Expected value / note | How Paskia uses it |
|---|---|---|
| Host | Forwarded directly from the client | Verifying the session's bound host |
| Cookie | Forwarded directly or just cookie `__Host-paskia` | Session ID |
| X-Forwarded-Method | The HTTP method, e.g. POST | Logging of original request |
| X-Forwarded-Uri | Request path and query, e.g. /reports?foo=bar | Logging of original request |
| Accept | text/html or anything else | Determines whether failures return an HTML page or JSON |

Connection hop-by-hop headers (Connection, Upgrade, Transfer-Encoding, etc.) must not be forwarded.

## Response

### Success (204)

No response body. Only [Remote headers](../Headers.md) are set on the response and your proxy should forward them to the backend request. The headers, not a response body, are the whole point of this endpoint: they are how the authenticated identity reaches the protected service, which can trust them because it is only reachable through the proxy.

### Failure (401 / 403)

| Status | Meaning |
|---|---|
| 401 | Session missing or expired, or max_age not satisfied — the user needs to (re)authenticate. |
| 403 | Requested permissions are missing — the forbidden flow allows signing in with another account. |

Failure responses come in two flavors, chosen by the Accept header, because the audience differs:

- A browser asking for a page (Accept includes text/html) gets a full authentication page it can show directly — the proxy simply passes the response through and the user can sign in without any application involvement.
- Any other request (fetch, img, ...) gets JSON intended for programmatic handling. Besides the error detail, it carries an auth section whose iframe URL points to a ready-made authentication dialog your frontend can embed, so the user can sign in without leaving your app:

```json
{
  "detail": "Additional authentication required",
  "auth": {
    "mode": "reauth",
    "iframe": "/auth/restricted/iframe#mode=reauth&theme=dark"
  }
}
```

The mode field:
- login: no valid session, need to sign in
- reauth: additional authentication required (using same passkey)
- forbidden: lacking required permissions

Extra metadata such as the user's theme override may appear as additional fields and iframe fragment parameters.

Note: we provide a JavaScript package [paskia](https://www.npmjs.com/package/paskia) with helpers for the embedding, fetch 401/403 handling, session renewals and more.

## Session renewal

The forward endpoint **does not renew** the session because in the forward-auth mechanism it could not send the client a renewed session cookie. It only validates the current cookie and returns the trusted headers. Use [/auth/api/validate](validate.md) when you need to refresh the session lifetime. Otherwise the user will have to sign in again every 24h even if they are actively using the service.
