import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'

export async function register(url, options) {
  if (options) url += `?${new URLSearchParams(options).toString()}`
  const ws = await aWebSocket(url)
  try {
    const optionsJSON = await ws.receive_json()
    const registrationResponse = await startRegistration({ optionsJSON })
    ws.send_json(registrationResponse)
    const result = await ws.receive_json()
  } catch (error) {
    console.error('Registration error:', error)
     // Replace useless and ugly error message from startRegistration
    throw Error(error.name === "NotAllowedError" ? 'Passkey registration cancelled' : error.message)
  } finally {
    ws.close()
  }
}

export async function registerUser(user_name) {
  return register('/auth/ws/register', { user_name })
}

export async function registerCredential() {
  return register('/auth/ws/add_credential')
}
export async function registerWithToken(token) {
  return register('/auth/ws/add_credential', { token })
}

export async function authenticateUser() {
  const ws = await aWebSocket('/auth/ws/authenticate')
  try {
    const optionsJSON = await ws.receive_json()
    const authResponse = await startAuthentication({ optionsJSON })
    ws.send_json(authResponse)
    const result = await ws.receive_json()
    return result
  } catch (error) {
    console.error('Authentication error:', error)
    throw Error(error.name === "NotAllowedError" ? 'Passkey authentication cancelled' : error.message)
  } finally {
    ws.close()
  }
}
