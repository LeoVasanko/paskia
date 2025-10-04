import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'
import { getSettings } from '@/utils/settings'

// Generic path normalizer: if an auth_host is configured and differs from current
// host, return absolute URL (scheme derived by aWebSocket). Otherwise, keep as-is.
async function makeUrl(path) {
  const s = await getSettings()
  const h = s?.auth_host
  return h && location.host !== h ? `//${h}${path}` : path
}

export async function register(resetToken = null, displayName = null) {
  let params = []
  if (resetToken) params.push(`reset=${encodeURIComponent(resetToken)}`)
  if (displayName) params.push(`name=${encodeURIComponent(displayName)}`)
  const qs = params.length ? `?${params.join('&')}` : ''
  const ws = await aWebSocket(await makeUrl(`/auth/ws/register${qs}`))
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
  const ws = await aWebSocket(await makeUrl('/auth/ws/authenticate'))
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
