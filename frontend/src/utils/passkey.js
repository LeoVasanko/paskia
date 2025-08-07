import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'

export async function register() {
  const ws = await aWebSocket("/auth/ws/register")
  try {
    const optionsJSON = await ws.receive_json()
    const registrationResponse = await startRegistration({ optionsJSON })
    ws.send_json(registrationResponse)
    return await ws.receive_json()
  } catch (error) {
    console.error('Registration error:', error)
     // Replace useless and ugly error message from startRegistration
    throw Error(error.name === "NotAllowedError" ? 'Passkey registration cancelled' : error.message)
  } finally {
    ws.close()
  }
}

export async function authenticate() {
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

export default { authenticate, register }
