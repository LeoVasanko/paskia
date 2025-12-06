import { type Page } from '@playwright/test'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const stateFile = join(__dirname, '..', '..', 'test-data', 'test-state.json')

/**
 * WebSocket helpers for passkey registration and authentication.
 * These functions mirror the frontend's passkey.js but work in a Playwright context.
 */

export interface RegistrationResult {
  user_uuid: string
  credential_uuid: string
  session_token: string
  message: string
}

export interface AuthenticationResult {
  user_uuid: string
  session_token: string
}

/**
 * Get the bootstrap reset token from the test state file.
 */
export function getBootstrapResetToken(): string | undefined {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      return state.resetToken
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Get the session cookie name from the test state file.
 */
export function getSessionCookieName(): string {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      return state.sessionCookie || '__Host-auth'
    } catch {
      return '__Host-auth'
    }
  }
  return '__Host-auth'
}

/**
 * Save a session token to the test state file for sharing across test groups.
 */
export function saveSessionToken(sessionToken: string): void {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      state.savedSessionToken = sessionToken
      writeFileSync(stateFile, JSON.stringify(state, null, 2))
    } catch {
      // Ignore errors
    }
  }
}

/**
 * Clear the saved session token from the test state file.
 * Call this after logout to prevent accidental reuse of invalidated sessions.
 */
export function clearSavedSessionToken(): void {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      delete state.savedSessionToken
      writeFileSync(stateFile, JSON.stringify(state, null, 2))
    } catch {
      // Ignore errors
    }
  }
}

/**
 * Get a saved session token from the test state file.
 */
export function getSavedSessionToken(): string | undefined {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      return state.savedSessionToken
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Save device tokens to the test state file for use by other tests.
 * These tokens allow tests to register their own passkeys.
 */
export function saveDeviceTokens(tokens: string[]): void {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      state.deviceTokens = tokens
      writeFileSync(stateFile, JSON.stringify(state, null, 2))
    } catch {
      // Ignore errors
    }
  }
}

/**
 * Get and consume a device token from the pool.
 * Returns undefined if no tokens are available.
 */
export function popDeviceToken(): string | undefined {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      if (state.deviceTokens && state.deviceTokens.length > 0) {
        const token = state.deviceTokens.pop()
        writeFileSync(stateFile, JSON.stringify(state, null, 2))
        return token
      }
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Get the count of remaining device tokens.
 */
export function getDeviceTokenCount(): number {
  if (existsSync(stateFile)) {
    try {
      const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
      return state.deviceTokens?.length || 0
    } catch {
      return 0
    }
  }
  return 0
}

/**
 * Perform passkey registration via WebSocket.
 * This runs in the browser context using the virtual authenticator.
 */
export async function registerPasskey(
  page: Page,
  baseUrl: string,
  options: { resetToken?: string; displayName?: string } = {}
): Promise<RegistrationResult> {
  return await page.evaluate(async ({ baseUrl, resetToken, displayName }) => {
    // Build WebSocket URL with query parameters
    let wsUrl = `${baseUrl.replace('http', 'ws')}/auth/ws/register`
    const params: string[] = []
    if (resetToken) params.push(`reset=${encodeURIComponent(resetToken)}`)
    if (displayName) params.push(`name=${encodeURIComponent(displayName)}`)
    if (params.length) wsUrl += `?${params.join('&')}`

    return new Promise<any>((resolve, reject) => {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log('WebSocket connected for registration')
      }

      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data)

        // Check for error response
        if (data.detail) {
          ws.close()
          reject(new Error(data.detail))
          return
        }

        // Check if this is the final success response
        if (data.session_token) {
          ws.close()
          resolve(data)
          return
        }

        // This should be the registration options from server (wrapped in optionsJSON)
        // Use the native WebAuthn API with the virtual authenticator
        try {
          // Extract options from the optionsJSON wrapper
          const opts = data.optionsJSON

          // Convert base64url challenge to ArrayBuffer
          const challenge = Uint8Array.from(atob(opts.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))

          // Build the credential creation options
          const publicKeyCredentialCreationOptions: CredentialCreationOptions = {
            publicKey: {
              challenge: challenge,
              rp: {
                name: opts.rp.name,
                id: opts.rp.id,
              },
              user: {
                id: Uint8Array.from(atob(opts.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                name: opts.user.name,
                displayName: opts.user.displayName,
              },
              pubKeyCredParams: opts.pubKeyCredParams,
              authenticatorSelection: opts.authenticatorSelection,
              timeout: opts.timeout,
              attestation: opts.attestation,
              excludeCredentials: opts.excludeCredentials?.map((cred: any) => ({
                ...cred,
                id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
              })) || [],
            }
          }

          // Create the credential using native WebAuthn API (virtual authenticator handles it)
          const credential = await navigator.credentials.create(publicKeyCredentialCreationOptions) as PublicKeyCredential

          if (!credential) {
            throw new Error('Failed to create credential')
          }

          const response = credential.response as AuthenticatorAttestationResponse

          // Convert response to JSON format expected by server
          const registrationResponse = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
            response: {
              clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              attestationObject: btoa(String.fromCharCode(...new Uint8Array(response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              transports: response.getTransports?.() || [],
            },
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults(),
            authenticatorAttachment: (credential as any).authenticatorAttachment,
          }

          ws.send(JSON.stringify(registrationResponse))
        } catch (error: any) {
          ws.close()
          reject(new Error(error.message || 'Registration failed'))
        }
      }

      ws.onerror = () => {
        reject(new Error('WebSocket error during registration'))
      }

      ws.onclose = (event) => {
        if (!event.wasClean && event.code !== 1000) {
          reject(new Error(`WebSocket closed unexpectedly: ${event.code}`))
        }
      }
    })
  }, { baseUrl, resetToken: options.resetToken, displayName: options.displayName })
}

/**
 * Perform passkey authentication via WebSocket.
 * This runs in the browser context using the virtual authenticator.
 */
export async function authenticatePasskey(
  page: Page,
  baseUrl: string
): Promise<AuthenticationResult> {
  return await page.evaluate(async ({ baseUrl }) => {
    const wsUrl = `${baseUrl.replace('http', 'ws')}/auth/ws/authenticate`

    return new Promise<any>((resolve, reject) => {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log('WebSocket connected for authentication')
      }

      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data)

        // Check for error response
        if (data.detail) {
          ws.close()
          reject(new Error(data.detail))
          return
        }

        // Check if this is the final success response
        if (data.session_token) {
          ws.close()
          resolve(data)
          return
        }

        // This should be the authentication options from server (wrapped in optionsJSON)
        try {
          // Extract options from the optionsJSON wrapper
          const opts = data.optionsJSON

          // Convert base64url challenge to ArrayBuffer
          const challenge = Uint8Array.from(atob(opts.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))

          // Build the credential request options
          const publicKeyCredentialRequestOptions: CredentialRequestOptions = {
            publicKey: {
              challenge: challenge,
              rpId: opts.rpId,
              timeout: opts.timeout,
              userVerification: opts.userVerification,
              allowCredentials: opts.allowCredentials?.map((cred: any) => ({
                type: cred.type,
                id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                transports: cred.transports,
              })) || [],
            }
          }

          // Get the credential using native WebAuthn API (virtual authenticator handles it)
          const credential = await navigator.credentials.get(publicKeyCredentialRequestOptions) as PublicKeyCredential

          if (!credential) {
            throw new Error('Failed to get credential')
          }

          const response = credential.response as AuthenticatorAssertionResponse

          // Convert response to JSON format expected by server
          const authenticationResponse = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
            response: {
              clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              authenticatorData: btoa(String.fromCharCode(...new Uint8Array(response.authenticatorData))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              signature: btoa(String.fromCharCode(...new Uint8Array(response.signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              userHandle: response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(response.userHandle))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : null,
            },
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults(),
            authenticatorAttachment: (credential as any).authenticatorAttachment,
          }

          ws.send(JSON.stringify(authenticationResponse))
        } catch (error: any) {
          ws.close()
          reject(new Error(error.message || 'Authentication failed'))
        }
      }

      ws.onerror = () => {
        reject(new Error('WebSocket error during authentication'))
      }

      ws.onclose = (event) => {
        if (!event.wasClean && event.code !== 1000) {
          reject(new Error(`WebSocket closed unexpectedly: ${event.code}`))
        }
      }
    })
  }, { baseUrl })
}

/**
 * Validate a session token via the API.
 */
export async function validateSession(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<{ valid: boolean; user_uuid: string; renewed: boolean }> {
  const cookieName = getSessionCookieName()
  const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
    headers: {
      'Cookie': `${cookieName}=${sessionToken}`,
    },
  })
  return await response.json()
}

/**
 * Get user info via the API.
 */
export async function getUserInfo(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<any> {
  const cookieName = getSessionCookieName()
  const response = await page.request.post(`${baseUrl}/auth/api/user-info`, {
    headers: {
      'Cookie': `${cookieName}=${sessionToken}`,
    },
  })
  return await response.json()
}

/**
 * Logout via the API.
 * If the session being logged out matches the saved session token, clears it.
 */
export async function logout(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<void> {
  const cookieName = getSessionCookieName()
  await page.request.post(`${baseUrl}/auth/api/logout`, {
    headers: {
      'Cookie': `${cookieName}=${sessionToken}`,
    },
  })
  // Clear saved session token if it matches the one being logged out
  const savedToken = getSavedSessionToken()
  if (savedToken === sessionToken) {
    clearSavedSessionToken()
  }
}

/**
 * Create a device link for adding a new credential to an existing user.
 */
export async function createDeviceLink(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<{ url: string; token: string }> {
  const cookieName = getSessionCookieName()
  const response = await page.request.post(`${baseUrl}/auth/api/user/create-link`, {
    headers: {
      'Cookie': `${cookieName}=${sessionToken}`,
    },
  })
  if (!response.ok()) {
    throw new Error(`Failed to create device link: ${response.status()} - ${await response.text()}`)
  }
  const data = await response.json()
  if (!data.url) {
    throw new Error(`No URL in response: ${JSON.stringify(data)}`)
  }
  // Extract token from URL (last path segment)
  const url = new URL(data.url)
  const token = url.pathname.split('/').pop() || ''
  return { url: data.url, token }
}
