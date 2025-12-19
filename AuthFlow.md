# API Authentication Flow (iframe)

This document describes the frontend flow for handling `401/403` responses from endpoints protected by Paskia forward-auth, without ever exiting your app.

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

When a protected request fails, the backend returns 401 (needs auth / reauth) or 403 (missing permission). For API requests, the response is JSON that includes an iframe URL. Your app should render that URL in a full-screen iframe overlay, and retry the request after the iframe reports success. If it reports `auth-cancel`, don't try again. The backdrop for the dialog is a stylistic choice, and you can style the background shown with the dialog any way you wish, and consider using CSS file with the iframe rather than inline styles as used in the example.

If this seems too heavy for your needs, you can simply refresh the page or navigate to /auth/ but this will lose your app state and in the latter case affect navigation in a way that is not optimal.
