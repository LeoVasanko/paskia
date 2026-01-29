# Paskia

![Paskia](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/forbidden-light.webp)

JavaScript utilities for [Paskia authentication system](https://git.zi.fi/leovasanko/paskia) integration into web apps.

## Installation

### NPM

No framework dependencies. Works with any framework (Vue, React, Svelte, etc.) or vanilla JS. Typescript typing included.

```sh
npm install paskia
```

```js
import { ... } from 'paskia'
```

### Plain JavaScript

Fetch the module directly from a CDN, or [download](https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js) first and host yourself. No Node needed.

```html
<script type="module">
  import { ... } from 'https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js'
</script>
```

## Features

### Session Validation

Refresh session and track its validity with automatic polling. Pauses on lack of user activity to avoid useless traffic and to allow session expiry even when the page is left open but idle. This monitors that the same account stays logged in but doesn't do any permission checks.

```js
import { SessionValidator } from 'paskia'

const validator = new SessionValidator(
  () => currentUser?.uuid,  // getter for current user ID that we track
  (error) => handleSessionLost(error)  // callback when session is lost
)

validator.start()  // call at your app startup/login
validator.stop()   // stop the system (optional)
```

### API Fetch Utilities

Enhanced fetch functions with automatic error handling and authentication retry:

```js
import { apiJson, apiFetch } from 'paskia'

// JSON API calls with automatic auth handling
const data = await apiJson('/api/endpoint', { method: 'POST', body: { key: 'value' } })

// Raw fetch with auth handling
const response = await apiFetch('/api/endpoint')
```

When a 401/403 response includes an auth iframe URL, the request automatically pauses, displays the authentication UI, and retries upon success. In case this is not needed, use standard `fetch` or our `fetchJson`.

The JSON variants set headers automatically, with body and response in JSON.

### Authentication Overlay

Normally you use apiJson/apiFetch and they handle this automatically. If you need to wire it yourself, on a 401/403 response that includes `auth.iframe`, call `showAuthIframe(...)` and then retry the original request.

The backend returns 401/403 responses with the correct URL for proper user feedback. Alternatively you may use `/auth/restricted/#mode=login`, `mode=reauth` or `mode=forbidden` to trigger the UX flow you need.

```js
import { showAuthIframe, AuthCancelledError } from 'paskia'

const response = await fetch('/api/protected')
if (response.status === 401 || response.status === 403) {
  const data = await response.json()
  if (data.auth?.iframe) {
    await showAuthIframe(data.auth.iframe)  // Raises AuthCancelledError if the user cancels
  }
}
```

This resolves after the user authenticates (possibly with another account than previously), and you should usually retry the original API request. Note that successful authentication doesn't guarantee that the user still has rights to what originally failed.

### Shared Blur Backdrop

The authentication dialog displays with a blur backdrop (z-index 1099). The auth iframe uses z-index 9999. Your app dialogs should use z-index 1100–9998 to appear above the backdrop but below authentication.

The backdrop is also reusable/refcounted, so you can keep consistent visuals for your own dialogs:

```js
import { holdGlobalBackdrop, releaseGlobalBackdrop } from 'paskia'

holdGlobalBackdrop()
try {
  await your.own.dialog()
} finally {
  releaseGlobalBackdrop()
}
```

The backdrop only disappears after all holders have released it.

## Error Handling

### AuthCancelledError (apiFetch, apiJson, showAuthIframe)

If the user clicks Back in the authentication dialog, refusing to authenticate, `AuthCancelledError` is risen (as a response to postMessage from the iframe). The dialog closes as expected and it is up to the app how to continue from there.

- Do nothing if the app can continue despite the failed operation (no UI notification needed)
- Display a simple Access Denied page with suggestion/button to reload the page to try again

Do not retry automatically.

### UI feedback

A set of small utilities are available for determining whether the user needs a notification and to format the error message.

```js
import { getUserFriendlyErrorMessage, shouldShowErrorToast } from 'paskia'

try {
  await apiJson('/api/action')
} catch (e) {
  if (shouldShowErrorToast(e)) {
    your.message.display(getUserFriendlyErrorMessage(e))
  }
}
```
