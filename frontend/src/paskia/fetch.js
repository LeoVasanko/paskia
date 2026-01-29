import { showAuthIframe, AuthCancelledError } from './overlay'

export { AuthCancelledError }

const DEFAULT_TIMEOUT_MS = 1000

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

export class NetworkError extends Error {
  constructor(message, originalError = null) {
    super(message)
    this.name = 'NetworkError'
    this.originalError = originalError
  }
}

export async function apiFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT_MS, ...fetchOptions } = options
  fetchOptions.credentials = fetchOptions.credentials || 'include'

  while (true) {
    let response
    try {
      response = await fetch(url, {...fetchOptions, signal: timeout && AbortSignal.timeout(timeout)})
    } catch (error) {
      if (error.name === 'TimeoutError') {
        throw new NetworkError('Request timed out', error)
      }
      if (error.name === 'AbortError') {
        throw error
      }
      if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
        throw new NetworkError('Unable to connect to server', error)
      }
      throw new NetworkError(error.message || 'Network error', error)
    }

    if (response.status === 401 || response.status === 403) {
      let data = null
      try {
        data = await response.clone().json()
      } catch {}
      if (data.auth?.iframe && window === window.top) {
        await showAuthIframe(data.auth.iframe)
        continue  // Retry the original request after successful auth
      }
    }

    return response
  }
}

export async function apiJson(url, options = {}) {
  return fetchJson(url, options, apiFetch)
}

export async function fetchJson(url, options = {}, fetchFn = fetch) {
  const opt = { ...options }

  opt.headers = {
    'Accept': 'application/json',
    ...opt.headers,
  }

  if (opt.body && typeof opt.body === 'object' && !(opt.body instanceof FormData)) {
    opt.headers = {
      'Content-Type': 'application/json',
      ...opt.headers,
    }
    opt.body = JSON.stringify(opt.body)
  }

  const response = await fetchFn(url, opt)
  const data = await response.json()

  if (!response.ok) {
    throw new ApiError(url, response, data)
  }

  return data
}

export function getUserFriendlyErrorMessage(error) {
  if (error instanceof NetworkError) return error.message
  if (error instanceof ApiError) return error.message
  if (error.name === 'TimeoutError') return 'Request timed out'
  if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
    return 'Unable to connect to server'
  }
  return error.message || 'An error occurred'
}

export function shouldShowErrorToast(error) {
  if (error instanceof AuthCancelledError) return false
  if (error.name === 'AbortError') return false
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return false
  return true
}

export function createApiCaller(showMessage) {
  return async function apiCall(url, options = {}) {
    try {
      return await apiJson(url, options)
    } catch (error) {
      if (!shouldShowErrorToast(error)) {
        throw error
      }
      console.error(`API error for ${url}:`, error instanceof ApiError ? { status: error.status, statusText: error.statusText, data: error.data } : error)
      showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
      throw error
    }
  }
}

export default apiFetch
