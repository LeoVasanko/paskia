import { showAuthIframe, AuthCancelledError } from './overlay'

export { AuthCancelledError }

const DEFAULT_TIMEOUT_MS = 1000

export interface ApiFetchOptions extends RequestInit {
  timeout?: number
}

export interface FetchJsonOptions extends Omit<RequestInit, 'body'> {
  timeout?: number
  body?: BodyInit | Record<string, unknown> | null
}

export class ApiError extends Error {
  readonly url: string
  readonly status: number
  readonly statusText: string
  readonly data: unknown

  constructor(url: string, response: Response, data: unknown) {
    super((data as { detail?: string })?.detail || `Request failed: ${response.status}`)
    this.name = 'ApiError'
    this.url = url
    this.status = response.status
    this.statusText = response.statusText
    this.data = data
  }
}

export class NetworkError extends Error {
  readonly originalError: Error | null

  constructor(message: string, originalError: Error | null = null) {
    super(message)
    this.name = 'NetworkError'
    this.originalError = originalError
  }
}

export async function apiFetch(url: string, options: ApiFetchOptions = {}): Promise<Response> {
  const { timeout = DEFAULT_TIMEOUT_MS, ...fetchOptions } = options
  fetchOptions.credentials = fetchOptions.credentials || 'include'

  while (true) {
    let response: Response
    try {
      response = await fetch(url, {...fetchOptions, signal: timeout ? AbortSignal.timeout(timeout) : undefined})
    } catch (error) {
      const err = error as Error
      if (err.name === 'TimeoutError') {
        throw new NetworkError('Request timed out', err)
      }
      if (err.name === 'AbortError') {
        throw error
      }
      if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
        throw new NetworkError('Unable to connect to server', err)
      }
      throw new NetworkError(err.message || 'Network error', err)
    }

    if (response.status === 401 || response.status === 403) {
      let data: { auth?: { iframe?: string } } | null = null
      try {
        data = await response.clone().json()
      } catch {}
      if (data?.auth?.iframe && window === window.top) {
        await showAuthIframe(data.auth.iframe)
        continue  // Retry the original request after successful auth
      }
    }

    return response
  }
}

type FetchFn = (url: string, options?: RequestInit) => Promise<Response>

export async function apiJson<T = unknown>(url: string, options: FetchJsonOptions = {}): Promise<T> {
  return fetchJson<T>(url, options, apiFetch)
}

export async function fetchJson<T = unknown>(url: string, options: FetchJsonOptions = {}, fetchFn: FetchFn = fetch): Promise<T> {
  const headers: Record<string, string> = {
    'Accept': 'application/json',
    ...(options.headers as Record<string, string>),
  }

  let body: BodyInit | undefined
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  } else {
    body = options.body as BodyInit
  }

  const opt: RequestInit = { ...options, headers, body }

  const response = await fetchFn(url, opt)
  const data = await response.json() as T

  if (!response.ok) {
    throw new ApiError(url, response, data)
  }

  return data
}

export function getUserFriendlyErrorMessage(error: Error): string {
  if (error instanceof NetworkError) return error.message
  if (error instanceof ApiError) return error.message
  if (error.name === 'TimeoutError') return 'Request timed out'
  if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
    return 'Unable to connect to server'
  }
  return error.message || 'An error occurred'
}

export function shouldShowErrorToast(error: Error): boolean {
  if (error instanceof AuthCancelledError) return false
  if (error.name === 'AbortError') return false
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return false
  return true
}

type ShowMessageFn = (message: string, type: string, duration: number) => void

export function createApiCaller(showMessage: ShowMessageFn) {
  return async function apiCall<T = unknown>(url: string, options: FetchJsonOptions = {}): Promise<T> {
    try {
      return await apiJson<T>(url, options)
    } catch (error) {
      if (!shouldShowErrorToast(error as Error)) {
        throw error
      }
      const err = error as Error
      console.error(`API error for ${url}:`, err instanceof ApiError ? { status: err.status, statusText: err.statusText, data: err.data } : err)
      showMessage(getUserFriendlyErrorMessage(err), 'error', 4000)
      throw error
    }
  }
}

export default apiFetch
