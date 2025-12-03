/**
 * API fetch wrapper that handles authentication errors with iframe-based re-authentication.
 *
 * When a 401 or 403 response is received with an `auth` object containing `iframe` URL,
 * this wrapper shows an authentication iframe and retries the original request after
 * successful authentication.
 */

let authIframe = null
let authPromise = null
let authResolve = null
let authReject = null

/**
 * Show the authentication iframe and return a promise that resolves on success.
 * @param {string} iframeSrc - The URL for the iframe src
 * @returns {Promise<void>}
 */
function showAuthIframe(iframeSrc) {
  // If already showing auth, return existing promise
  if (authPromise) return authPromise

  authPromise = new Promise((resolve, reject) => {
    authResolve = resolve
    authReject = reject
  })

  // Remove existing iframe if any
  hideAuthIframe()

  // Create new iframe for authentication
  authIframe = document.createElement('iframe')
  authIframe.id = 'auth-iframe'
  authIframe.title = 'Authentication'
  authIframe.src = iframeSrc
  document.body.appendChild(authIframe)

  return authPromise
}

function hideAuthIframe() {
  if (authIframe) {
    authIframe.remove()
    authIframe = null
  }
}

function handleAuthMessage(event) {
  const data = event.data
  if (!data?.type) return

  switch (data.type) {
    case 'auth-success':
      hideAuthIframe()
      if (authResolve) {
        authResolve()
        authPromise = null
        authResolve = null
        authReject = null
      }
      break

    case 'auth-back':
    case 'auth-close-request':
      hideAuthIframe()
      if (authReject) {
        authReject(new Error('Authentication cancelled'))
        authPromise = null
        authResolve = null
        authReject = null
      }
      break

    case 'auth-error':
      // Keep iframe open for retry, but if cancelled, treat as back
      if (data.cancelled && authReject) {
        hideAuthIframe()
        authReject(new Error('Authentication cancelled'))
        authPromise = null
        authResolve = null
        authReject = null
      }
      break
  }
}

// Install global message listener
if (typeof window !== 'undefined') {
  window.addEventListener('message', handleAuthMessage)
}

/**
 * Fetch wrapper that handles auth errors with iframe-based re-authentication.
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<Response>} - The fetch response
 * @throws {Error} - If authentication is cancelled or fails
 */
export async function apiFetch(url, options = {}) {
  // Ensure credentials are included for cookie-based auth
  const fetchOptions = {
    ...options,
    credentials: options.credentials || 'include',
  }

  const response = await fetch(url, fetchOptions)

  // Check for auth errors (401/403)
  if (response.status === 401 || response.status === 403) {
    // Try to parse the response to get the iframe URL
    let authInfo = null
    try {
      const data = await response.clone().json()
      authInfo = data.auth
    } catch {
      // If we can't parse JSON, fall back to default iframe URL
    }

    if (authInfo?.iframe) {
      // Show auth iframe and wait for success
      await showAuthIframe(authInfo.iframe)

      // Retry the original request
      return fetch(url, fetchOptions)
    }
  }

  return response
}

/**
 * Convenience method for JSON API calls.
 * Automatically sets Content-Type for POST/PUT/PATCH with body.
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<any>} - Parsed JSON response
 * @throws {Error} - If response has error detail or auth fails
 */
export async function apiJson(url, options = {}) {
  const fetchOptions = { ...options }

  // Set Content-Type for requests with JSON body
  if (fetchOptions.body && typeof fetchOptions.body === 'object' && !(fetchOptions.body instanceof FormData)) {
    fetchOptions.headers = {
      'Content-Type': 'application/json',
      ...fetchOptions.headers,
    }
    fetchOptions.body = JSON.stringify(fetchOptions.body)
  }

  const response = await apiFetch(url, fetchOptions)
  const data = await response.json()

  if (!response.ok || data.detail) {
    throw new Error(data.detail || `Request failed: ${response.status}`)
  }

  return data
}

export default apiFetch
