import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'

export async function register(url, options) {
  if (options) url += `?${new URLSearchParams(options).toString()}`
  const ws = await aWebSocket(url)

  const optionsJSON = await ws.receive_json()
  const registrationResponse = await startRegistration({ optionsJSON })
  ws.send_json(registrationResponse)

  const result = await ws.receive_json()
  ws.close()
  return result;
}

export async function registerUser(user_name) {
  return register('/auth/ws/new_user_registration', { user_name })
}

export async function registerCredential() {
  return register('/auth/ws/add_credential')
}
export async function registerWithToken(token) {
  return register('/auth/ws/add_device_credential', {token})
}

export async function authenticateUser() {
  const ws = await aWebSocket('/auth/ws/authenticate')

  const optionsJSON = await ws.receive_json()
  const authResponse = await startAuthentication({ optionsJSON })
  ws.send_json(authResponse)

  const result = await ws.receive_json()
  ws.close()
  return result
}
