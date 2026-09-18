![Screenshot](https://git.zi.fi/leovasanko/paskia/raw/main/docs/screenshots/forbidden-light.webp)

# Paskia

JavaScript utilities for integrating the [Paskia authentication system](https://git.zi.fi/leovasanko/paskia) into web apps.

## Installation

### npm

No framework dependencies. Works with Vue, React, Svelte, vanilla JavaScript and other frontend stacks. TypeScript types are included.

```sh
npm install paskia
```

```js
import { ... } from 'paskia'
```

### Plain JavaScript

Import directly from a CDN, or [download](https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js) and host it yourself. No Node.js is required.

```html
<script type="module">
  import { ... } from 'https://cdn.jsdelivr.net/npm/paskia@latest/dist/paskia.js'
</script>
```

## Authentication

### API requests

`apiFetch` wraps `fetch` with Paskia authentication handling, while `apiJson` adds automatic JSON request/response handling. Both support request timeouts. For the same JSON and timeout handling without prompting the user for authentication, use `fetchJson`.

```js
import { apiJson, apiFetch } from 'paskia'

const data = await apiJson('/api/endpoint', {
  method: 'POST',
  body: { key: 'value' }
})

const response = await apiFetch('/api/endpoint')
```

With `apiJson`, a provided `body` is JSON-encoded with the appropriate content type and the response is parsed as JSON.

When the server requests authentication, the API call pauses while the appropriate Paskia dialog is shown and retries after successful authentication.

> Paskia uses `401` and `403` responses to trigger the appropriate **login**, **reauthentication** or **access denied** flow. The backend supplies the authentication URL and context; see the main Paskia documentation for the full response protocol.

### Account and Profile

`profile()` provides a single dialog for an application's login/profile button that allows the user to sign in, view who they are and sign out without ever leaving the page.

```js
import { profile } from 'paskia'

const result = await profile()
if (result !== 'back')  // Refresh application state
```

When signed out, it presents the login flow and returns `'login'` on success. When signed in, it shows the profile and returns `'logout'` after logout. `'back'` is returned when the dialog is closed without an expected session change.

Authentication and profile dialogs follow the user's theme override when set in profile, otherwise the host page's light/dark `color-scheme` to remain in the application's color scheme, then the browser/OS preference.

### Lower-level Authentication

`apiFetch` and `apiJson` call `showAuthIframe()` internally. Applications using plain `fetch` or `fetchJson` can call it directly with an authentication URL returned by the backend:

```js
import { showAuthIframe } from 'paskia'

await showAuthIframe(data.auth.iframe)
```

## Session Validation

`SessionValidator` periodically checks that the active Paskia session is still valid and still belongs to the user your application currently has loaded. Validation also refreshes the session to avoid expiry during use.

```js
import { SessionValidator } from 'paskia'

const validator = new SessionValidator(
  () => currentUser?.uuid,  // User ID currently known by your app
  error => handleSessionLost(error)
)

validator.start()
validator.stop()
```

The first callback is read on each check, so a logout, expired session or switch to another account invalidates the session your app is currently using. Polling pauses while the user is inactive, avoiding unnecessary traffic and allowing idle sessions to expire.

## Timeout Settings

Paskia exports mutable defaults for network and session timers:

```js
import { settings } from 'paskia'

settings.fetch_ms = 10000   // apiFetch, apiJson and fetchJson timeout
settings.auth_ms = 1000     // Session validation request timeout
settings.poll_ms = 60000    // Session validation interval
settings.idle_ms = 300000   // Inactivity before validation pauses
```

Request timeout can also be overridden per call:

```js
await apiJson('/api/upload', {
  method: 'POST',
  body: data,
  timeout: 30000
})
```

## Shared Blur Backdrop

A shared backdrop provides consistent UX across your application, avoiding different things stacking with their own backdrops and dialogs in unexpected manner.

Paskia dialogs use a shared blurred backdrop at z-index `1099` and the authentication iframe at `9999`. Application dialogs can use `1100`–`9998` to appear between them.

The same refcounted backdrop can be used by application UI:

```js
import { holdGlobalBackdrop, releaseGlobalBackdrop } from 'paskia'

holdGlobalBackdrop()
try {
  await your.own.dialog()
} finally {
  releaseGlobalBackdrop()
}
```

It disappears after all holders release it, also avoiding awkward fade/appear animations when changing between multiple dialogs.

## Error Handling

### `AuthCancelledError`

`apiFetch`, `apiJson` and `showAuthIframe` raise `AuthCancelledError` when the user cancels required authentication with Back or Escape. This means the user does not wish to authenticate, and should not be asked again.

Continue without the failed operation when possible, or show an appropriate terminal view when authentication is required to continue.

When the error is a direct result of a user action, we don't want to show an additional message for that, while in other situations we should. Helpers determine whether an error needs user notification and provide a suitable message:

```js
import { getUserFriendlyErrorMessage, shouldShowErrorToast } from 'paskia'

try {
  await apiJson('/api/action')
} catch (error) {
  if (shouldShowErrorToast(error)) {
    your.message.display(getUserFriendlyErrorMessage(error))
  }
}
```
