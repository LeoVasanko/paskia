import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'
import { getSettings } from '@/utils/settings'
import { showAuthIframe } from '@/utils/api'

// Generic path normalizer: if an auth_host is configured and differs from current
// host, return absolute URL (scheme derived by aWebSocket). Otherwise, keep as-is.
async function makeUrl(path) {
  const s = await getSettings()
  const h = s?.auth_host
  return h && location.host !== h ? `//${h}${path}` : path
}

export async function register(resetToken = null, displayName = null, onstartreg = null) {
  let params = []
  if (resetToken) params.push(`reset=${encodeURIComponent(resetToken)}`)
  if (displayName) params.push(`name=${encodeURIComponent(displayName)}`)
  const qs = params.length ? `?${params.join('&')}` : ''

  while (true) {
    const ws = await aWebSocket(await makeUrl(`/auth/ws/register${qs}`))
    try {
      const res = await ws.receive_json()

      // Handle auth errors (401/403) with iframe
      if ((res.status === 401 || res.status === 403) && res.data.auth?.iframe) {
        ws.close()
        await showAuthIframe(res.data.auth.iframe)
        continue
      }

      // Handle other errors
      if (!res.ok) {
        throw new Error(res.data.detail || `Registration failed: ${res.status}`)
      }

      // Notify caller that we're about to show the browser prompt
      if (onstartreg) onstartreg()

      const registrationResponse = await startRegistration({ optionsJSON: res.data })
      ws.send_json(registrationResponse)

      const result = await ws.receive_json()
      if (!result.ok) {
        throw new Error(result.data.detail || `Registration failed: ${result.status}`)
      }
      return result.data
    } catch (error) {
      ws.close()
      console.error('Registration error:', error)
      // Replace useless and ugly error message from startRegistration
      throw Error(error.name === "NotAllowedError" ? 'Passkey registration cancelled' : error.message)
    }
  }
}

export async function authenticate() {
  const ws = await aWebSocket(await makeUrl('/auth/ws/authenticate'))
  try {
    const res = await ws.receive_json()
    if (!res.ok) {
      throw new Error(res.data.detail || `Authentication failed: ${res.status}`)
    }

    const authResponse = await startAuthentication({ optionsJSON: res.data })
    ws.send_json(authResponse)

    const result = await ws.receive_json()
    if (!result.ok) {
      throw new Error(result.data.detail || `Authentication failed: ${result.status}`)
    }
    return result.data
  } catch (error) {
    console.error('Authentication error:', error)
    throw Error(error.name === "NotAllowedError" ? 'Passkey authentication cancelled' : error.message)
  } finally {
    ws.close()
  }
}

export default { authenticate, register }
