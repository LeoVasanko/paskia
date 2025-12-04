/**
 * API fetch wrapper that handles authentication errors with iframe-based re-authentication.
 *
 * When a 401 or 403 response is received with an `auth` object containing `iframe` URL,
 * this wrapper shows an authentication iframe and retries the original request after
 * successful authentication.
 */

/** Default timeout for API requests in milliseconds */
const DEFAULT_TIMEOUT_MS = 1000

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
 * Custom error class for network/timeout errors.
 */
export class NetworkError extends Error {
  constructor(message, originalError = null) {
    super(message)
    this.name = 'NetworkError'
    this.originalError = originalError
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

// Cache for auth iframe URL by mode
const authIframeUrlCache = {}

/**
 * Get the auth iframe URL for a given mode.
 * Fetches from /auth/api/forward which returns URL in the auth.iframe field.
 * Results are cached per mode.
 * @param {string} mode - The auth mode ('login', 'reauth', 'forbidden')
 * @returns {Promise<string>} - The URL for the iframe
 */
export async function getAuthIframeUrl(mode = 'login') {
  if (authIframeUrlCache[mode]) {
    return authIframeUrlCache[mode]
  }

  // Fetch from forward endpoint - it returns URL in auth.iframe on 401/403
  const response = await fetch('/auth/api/forward', { credentials: 'include' })
  if (response.status === 401 || response.status === 403) {
    const data = await response.json()
    if (data.auth?.iframe) {
      // The iframe field now contains a URL with hash fragment
      // If mode differs, update the hash param
      let url = data.auth.iframe
      if (mode !== data.auth.mode) {
        url = url.replace(/mode=[^&]*/, `mode=${mode}`)
      }
      authIframeUrlCache[mode] = url
      return url
    }
  }
  throw new Error('Unable to fetch auth iframe URL')
}

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
 * @param {string} iframeUrl - The URL for the iframe src
 * @returns {Promise<void>}
 * @throws {AuthCancelledError} - If authentication is cancelled by user
 */
export function showAuthIframe(iframeUrl) {
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

  // Create new iframe for authentication using src URL
  authIframe = document.createElement('iframe')
  authIframe.id = 'auth-iframe'
  authIframe.title = 'Authentication'
  authIframe.allow = 'publickey-credentials-get; publickey-credentials-create'
  authIframe.src = iframeUrl
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
 * @param {number} [options.timeout] - Timeout in ms (default: 10000, use 0 to disable)
 * @returns {Promise<Response>} - The fetch response
 * @throws {AuthCancelledError} - If authentication is cancelled by user
 * @throws {NetworkError} - If network error or timeout occurs
 */
export async function apiFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT_MS, ...fetchOptions } = options

  // Ensure credentials are included for cookie-based auth
  fetchOptions.credentials = fetchOptions.credentials || 'include'

  while (true) {
    let response
    try {
      response = await fetch(url, {...fetchOptions, signal: timeout && AbortSignal.timeout(timeout)})
    } catch (error) {
      // Handle network errors and timeouts
      if (error.name === 'TimeoutError') {
        throw new NetworkError('Request timed out', error)
      }
      if (error.name === 'AbortError') {
        // Re-throw abort errors as-is (user-initiated cancellation)
        throw error
      }
      if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
        throw new NetworkError('Unable to connect to server', error)
      }
      throw new NetworkError(error.message || 'Network error', error)
    }

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

      // Authenticate via iframe (only in top-level window)
      if (authInfo?.iframe && window === window.top) {
        // Show auth iframe (or wait for existing one) and retry on success
        // showAuthIframe returns existing promise if iframe is already open
        await showAuthIframe(authInfo.iframe)
        continue  // Retry the original request
      }
    }

    return response
  }
}

/**
 * Convenience method for JSON API calls.
 * Automatically sets Accept and Content-Type headers.
 * Returns parsed JSON directly if response is ok, throws ApiError otherwise.
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<any>} - Parsed JSON response
 * @throws {ApiError} - If response is not ok
 * @throws {NetworkError} - If network error or timeout occurs
 * @throws {AuthCancelledError} - If authentication is cancelled by user
 */
export async function apiJson(url, options = {}) {
  const fetchOptions = { ...options }

  // Set default headers, allowing caller overrides
  fetchOptions.headers = {
    'Accept': 'application/json',
    ...fetchOptions.headers,
  }

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
 * Simple JSON fetch without auto-auth iframe handling.
 * Use this in contexts where showing an auth iframe would be inappropriate
 * (e.g., inside the auth iframe itself).
 *
 * @param {string|URL} url - The URL to fetch
 * @param {RequestInit} [options] - Fetch options
 * @returns {Promise<any>} - Parsed JSON response
 * @throws {ApiError} - If response is not ok
 */
export async function fetchJson(url, options = {}) {
  const fetchOptions = {
    credentials: 'include',
    ...options,
    headers: {
      'Accept': 'application/json',
      ...options.headers,
    },
  }

  const response = await fetch(url, fetchOptions)
  const data = await response.json()

  if (!response.ok) {
    throw new ApiError(url, response, data)
  }

  return data
}

/**
 * Convert an error to a user-friendly message.
 * @param {Error} error - The error to convert
 * @returns {string} - User-friendly error message
 */
export function getUserFriendlyErrorMessage(error) {
  if (error instanceof NetworkError) {
    return error.message
  }
  if (error instanceof ApiError) {
    return error.message
  }
  if (error.name === 'TimeoutError') {
    return 'Request timed out'
  }
  if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
    return 'Unable to connect to server'
  }
  return error.message || 'An error occurred'
}

/**
 * Check if an error should show a toast to the user.
 * @param {Error} error - The error to check
 * @returns {boolean} - Whether to show a toast
 */
export function shouldShowErrorToast(error) {
  // Don't show toast for user cancellations
  if (error instanceof AuthCancelledError) return false
  if (error.name === 'AbortError') return false
  // Don't show toast for 401/403 errors - the auth iframe will handle these
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return false
  return true
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
      if (!shouldShowErrorToast(error)) {
        throw error
      }
      // Log full error details
      console.error(`API error for ${url}:`, error instanceof ApiError ? { status: error.status, statusText: error.statusText, data: error.data } : error)
      // Show user-friendly toast
      showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
      throw error
    }
  }
}

export default apiFetch
