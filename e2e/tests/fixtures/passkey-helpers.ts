import { type Page } from '@playwright/test'
import { existsSync, readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

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
  const stateFile = join(__dirname, '..', '..', 'test-data', 'test-state.json')
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

        // This should be the registration options from server
        // Use the native WebAuthn API with the virtual authenticator
        try {
          // Convert base64url challenge to ArrayBuffer
          const challenge = Uint8Array.from(atob(data.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))

          // Build the credential creation options
          const publicKeyCredentialCreationOptions: CredentialCreationOptions = {
            publicKey: {
              challenge: challenge,
              rp: {
                name: data.rp.name,
                id: data.rp.id,
              },
              user: {
                id: Uint8Array.from(atob(data.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                name: data.user.name,
                displayName: data.user.displayName,
              },
              pubKeyCredParams: data.pubKeyCredParams,
              authenticatorSelection: data.authenticatorSelection,
              timeout: data.timeout,
              attestation: data.attestation,
              excludeCredentials: data.excludeCredentials?.map((cred: any) => ({
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

        // This should be the authentication options from server
        try {
          // Convert base64url challenge to ArrayBuffer
          const challenge = Uint8Array.from(atob(data.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))

          // Build the credential request options
          const publicKeyCredentialRequestOptions: CredentialRequestOptions = {
            publicKey: {
              challenge: challenge,
              rpId: data.rpId,
              timeout: data.timeout,
              userVerification: data.userVerification,
              allowCredentials: data.allowCredentials?.map((cred: any) => ({
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
  const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
    headers: {
      'Cookie': `__Host-auth=${sessionToken}`,
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
  const response = await page.request.post(`${baseUrl}/auth/api/user-info`, {
    headers: {
      'Cookie': `__Host-auth=${sessionToken}`,
    },
  })
  return await response.json()
}

/**
 * Logout via the API.
 */
export async function logout(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<void> {
  await page.request.post(`${baseUrl}/auth/api/logout`, {
    headers: {
      'Cookie': `__Host-auth=${sessionToken}`,
    },
  })
}

/**
 * Create a device link for adding a new credential to an existing user.
 */
export async function createDeviceLink(
  page: Page,
  baseUrl: string,
  sessionToken: string
): Promise<{ url: string; token: string }> {
  const response = await page.request.post(`${baseUrl}/auth/api/user/create-link`, {
    headers: {
      'Cookie': `__Host-auth=${sessionToken}`,
    },
  })
  const data = await response.json()
  // Extract token from URL (last path segment)
  const url = new URL(data.url)
  const token = url.pathname.split('/').pop() || ''
  return { url: data.url, token }
}
