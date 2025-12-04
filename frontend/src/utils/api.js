/**
 * API fetch wrapper that handles authentication errors with iframe-based re-authentication.
 *
 * When a 401 or 403 response is received with an `auth` object containing `iframe` URL,
 * this wrapper shows an authentication iframe and retries the original request after
 * successful authentication.
 */

/**
 * Custom error class for API errors with full response context.
 */
export class ApiError extends Error {
  constructor(url, response, data) {
    super(data?.detail || `Request failed: ${response.status}`)
    this.name = 'ApiError'
    this.url = url
    this.status = response.status
    this.statusText = response.statusText
    this.data = data
  }
}

/**
 * Error thrown when user cancels authentication.
 */
export class AuthCancelledError extends Error {
  constructor() {
    super('Authentication cancelled')
    this.name = 'AuthCancelledError'
  }
}

let authIframe = null
let authPromise = null
let authResolve = null
let authReject = null

/**
 * Check if an auth iframe is already open (from any source).
 * @returns {boolean}
 */
export function isAuthIframeOpen() {
  return !!document.getElementById('auth-iframe')
}

/**
 * Show the authentication iframe and return a promise that resolves on success.
 * If an auth iframe is already open (from any source), hooks into its completion.
 * @param {string} iframeSrc - The URL for the iframe src
 * @returns {Promise<void>}
 * @throws {AuthCancelledError} - If authentication is cancelled by user
 */
export function showAuthIframe(iframeSrc) {
  // If we already have a promise (from us), return it
  if (authPromise) return authPromise

  // If there's already an iframe in the DOM (from App.vue or elsewhere),
  // create a promise that hooks into the message handler
  if (document.getElementById('auth-iframe')) {
    authPromise = new Promise((resolve, reject) => {
      authResolve = resolve
      authReject = reject
    })
    return authPromise
  }

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
        authReject(new AuthCancelledError())
        authPromise = null
        authResolve = null
        authReject = null
      }
      break

    case 'auth-error':
      // Keep iframe open for retry, but if cancelled, treat as back
      if (data.cancelled && authReject) {
        hideAuthIframe()
        authReject(new AuthCancelledError())
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
 * Loops until successful or user cancels authentication.
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<Response>} - The fetch response
 * @throws {AuthCancelledError} - If authentication is cancelled by user
 */
export async function apiFetch(url, options = {}) {
  // Ensure credentials are included for cookie-based auth
  const fetchOptions = {
    ...options,
    credentials: options.credentials || 'include',
  }

  while (true) {
    const response = await fetch(url, fetchOptions)

    // Check for auth errors (401/403)
    if (response.status === 401 || response.status === 403) {
      // Try to parse the response to get the iframe URL
      let authInfo = null
      try {
        const data = await response.clone().json()
        authInfo = data.auth
      } catch {
        // If we can't parse JSON, no iframe available
      }

      if (authInfo?.iframe) {
        // If an auth iframe is already open (from app or another request), don't open another
        // Just return the response so the caller can handle it
        if (isAuthIframeOpen()) {
          return response
        }
        // Show auth iframe and wait for success (throws AuthCancelledError on cancel)
        await showAuthIframe(authInfo.iframe)
        // Loop to retry the original request
        continue
      }
    }

    return response
  }
}

/**
 * Convenience method for JSON API calls.
 * Automatically sets Content-Type for POST/PUT/PATCH with body.
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<any>} - Parsed JSON response
 * @throws {ApiError} - If response has error detail or request fails
 * @throws {AuthCancelledError} - If authentication is cancelled by user
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

  if (!response.ok) {
    throw new ApiError(url, response, data)
  }

  return data
}

/**
 * Create an API caller with error handling (toast + console.error).
 * Wraps apiJson calls with consistent error handling for apps.
 *
 * @param {Function} showMessage - Function to show toast messages: (message, type, duration) => void
 * @returns {Function} - Wrapped apiJson that handles errors
 */
export function createApiCaller(showMessage) {
  /**
   * @param {string|URL} url - The URL to fetch
   * @param {RequestInit} [options] - Fetch options
   * @returns {Promise<any>} - Parsed JSON response, or undefined on error
   */
  return async function apiCall(url, options = {}) {
    try {
      return await apiJson(url, options)
    } catch (error) {
      if (error instanceof AuthCancelledError) {
        // User cancelled - don't show error toast, just re-throw
        throw error
      }
      // Log full error details
      console.error(`API error for ${url}:`, error instanceof ApiError ? { status: error.status, statusText: error.statusText, data: error.data } : error)
      // Show user-friendly toast
      showMessage(error.message || 'An error occurred', 'error')
      throw error
    }
  }
}

export default apiFetch
