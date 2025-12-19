# Integrating Paskia with your App

Protect API routes with forward-auth (see [Caddy configuration](Caddy.md)). Optionally protect your app assets and not just the API.

Catch response status 401/403 in fetch calls to protected endpoints and implement authentication flow in this case. The response is JSON and contains `detail` (an error message describing what is needed) and `auth.iframe` (a URL). Render that URL in an iframe and retry the request after authentication (see below).

While the app is in (active) use, call `/auth/api/validate` occasionally to keep the session alive (session lifetime is 24h), otherwise the user will have to login every day. Max-age limits are unaffected by this and can be used on endpoints needing to reauthenticate with passkey more frequently.

Fetch `/auth/api/user-info` to display user/session details, or link to `/auth/` if you prefer using the built-in profile UI and not having to do anything more.

## Authentication Flow (iframe)

```js
// Show an authentication dialog
const iframe = document.createElement('iframe')
iframe.src = auth.url   // from 401/403 response JSON
iframe.style.cssText = `
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  border: 0;
  z-index: 9999;
  background: transparent;
  backdrop-filter: blur(0.1rem) brightness(0.7);
`
document.body.appendChild(iframe)

// Wait until user is finished with the dialog
const handler = ev => {
  if (ev.origin !== location.origin) return
  iframe.remove()
  removeEventListener('message', handler)
  if (ev.data?.type === 'auth-success') retry_original_fetch()
}
addEventListener('message', handler)
```

This describes the frontend flow for handling 401/403 responses from endpoints protected by Paskia forward-auth, without ever exiting your app.

When a protected request fails, the backend returns 401 (needs auth / reauth) or 403 (missing permission). For API requests, the response is JSON that includes an iframe URL. Your app should render that URL in a full-screen iframe overlay, and retry the request after the iframe reports success. If it reports `auth-cancel`, don't try again. The backdrop for the dialog is a stylistic choice, and you can style the background shown with the dialog any way you wish, and consider using CSS file with the iframe rather than inline styles as used in the example.

Following this flow the user gets authenticated properly and after that your app keeps running as if nothing ever happened.
