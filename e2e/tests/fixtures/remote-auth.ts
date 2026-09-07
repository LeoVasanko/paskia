import { type Page } from '@playwright/test'

/**
 * Remote authentication (pairing code) helpers for E2E tests.
 * These drive the /auth/ws/remote-auth/* protocol directly in browser context,
 * so requests carry the page origin's cookies and Chrome's host resolution.
 */

// PBKDF2-SHA512 PoW solver; must match frontend/src/utils/pow.js.
// Passed as source into page.evaluate and instantiated with eval there.
const solvePoWSource = `async (challengeBytes, work) => {
  const baseKey = await crypto.subtle.importKey('raw', challengeBytes, 'PBKDF2', false, ['deriveBits'])
  const solution = new Uint8Array(8 * work)
  const nonce = new Uint32Array(2)
  const mask = 0x7FF
  for (let i = 0; i < work; i++) {
    let result
    do {
      if (++nonce[0] === 0x100000000) ++nonce[1]
      result = new Uint32Array(await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: nonce, iterations: 128, hash: 'SHA-512' }, baseKey, 32))
    } while (result[0] & mask)
    solution.set(new Uint8Array(nonce.buffer), i * 8)
  }
  return solution
}`

const b64helpersSource = `
  const b64dec = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
  const b64enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '')
`

/**
 * Start a remote auth request on the given page (the device wanting to log in).
 * The page must already be navigated to the requesting domain's origin.
 * Keeps the WebSocket open on window.__raWs and collects later messages into
 * window.__raMsgs; resolves with the pairing code.
 */
export async function startRemoteAuthRequest(page: Page): Promise<string> {
  return page.evaluate(async ({ powSrc, b64src }) => {
    const solvePoW = eval(`(${powSrc})`)
    const { b64dec, b64enc } = eval(`(() => { ${b64src}; return { b64dec, b64enc } })()`)
    const w = window as any
    w.__raMsgs = []
    return new Promise<string>((resolve, reject) => {
      const ws = new WebSocket(`ws://${location.host}/auth/ws/remote-auth/request`)
      w.__raWs = ws
      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data)
        w.__raMsgs.push(data)
        if (typeof data.status === 'number' && data.status >= 400) {
          ws.close()
          reject(new Error(data.detail || `request failed: ${data.status}`))
          return
        }
        if (data.pow && !data.pairing_code) {
          const solution = await solvePoW(b64dec(data.pow.challenge), data.pow.work)
          ws.send(JSON.stringify({ pow: b64enc(solution), action: 'login' }))
          return
        }
        if (data.pairing_code) {
          resolve(data.pairing_code)
        }
      }
      ws.onerror = () => reject(new Error('WebSocket error during remote auth request'))
      ws.onclose = (event) => {
        if (!event.wasClean && event.code !== 1000) reject(new Error(`WebSocket closed unexpectedly: ${event.code}`))
      }
    })
  }, { powSrc: solvePoWSource, b64src: b64helpersSource })
}

/**
 * Wait for the remote auth request on the page to complete, redeem the
 * exchange code via set-session, and return the /auth/api/validate response.
 */
export async function awaitRemoteAuthSession(page: Page, timeoutMs = 90000): Promise<any> {
  return page.evaluate(async ({ timeoutMs }) => {
    const w = window as any
    const msgs: any[] = w.__raMsgs
    if (!msgs) throw new Error('No remote auth request started on this page')
    const exchangeCode: string = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timed out waiting for remote auth completion')), timeoutMs)
      const iv = setInterval(() => {
        const done = msgs.find(m => m.status === 'authenticated' && m.exchange_code)
        const failed = msgs.find(m => ['denied', 'expired', 'timeout', 'cancelled'].includes(m.status) || (typeof m.status === 'number' && m.status >= 400))
        if (done) {
          clearTimeout(timer); clearInterval(iv)
          resolve(done.exchange_code)
        } else if (failed) {
          clearTimeout(timer); clearInterval(iv)
          reject(new Error(failed.detail || `Remote auth ${failed.status}`))
        }
      }, 50)
    })
    const resp = await fetch('/auth/api/set-session', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${exchangeCode}` },
    })
    if (!resp.ok) throw new Error(`set-session failed: ${resp.status}`)
    const validate = await fetch('/auth/api/validate', { method: 'POST' })
    if (!validate.ok) throw new Error(`validate failed: ${validate.status}`)
    return await validate.json()
  }, { timeoutMs })
}

/**
 * Permit a remote auth request from the given page (the authenticating device).
 * The page must be on the approver's origin with a valid session cookie and a
 * virtual authenticator holding a credential for that domain.
 * Resolves with the "found" message (includes the requesting domain's rp_id).
 */
export async function permitRemoteAuth(page: Page, code: string): Promise<any> {
  return page.evaluate(async ({ code, powSrc, b64src }) => {
    const solvePoW = eval(`(${powSrc})`)
    const { b64dec, b64enc } = eval(`(() => { ${b64src}; return { b64dec, b64enc } })()`)
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${location.host}/auth/ws/remote-auth/permit`)
      let stage = 0
      let foundMsg: any = null
      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data)
        try {
          if (typeof data.status === 'number' && data.status >= 400) {
            ws.close()
            reject(new Error(data.detail || `permit failed: ${data.status}`))
            return
          }
          if (data.pow && stage === 0) {
            const solution = await solvePoW(b64dec(data.pow.challenge), data.pow.work)
            stage = 1
            ws.send(JSON.stringify({ code, pow: b64enc(solution) }))
            return
          }
          if (data.status === 'found') {
            foundMsg = data
            const solution = await solvePoW(b64dec(data.pow.challenge), data.pow.work)
            stage = 2
            ws.send(JSON.stringify({ authenticate: true, pow: b64enc(solution) }))
            return
          }
          if (data.optionsJSON) {
            const opts = data.optionsJSON
            const credential = await navigator.credentials.get({
              publicKey: {
                challenge: b64dec(opts.challenge),
                rpId: opts.rpId,
                timeout: opts.timeout,
                userVerification: opts.userVerification,
                allowCredentials: opts.allowCredentials?.map((cred: any) => ({
                  type: cred.type,
                  id: b64dec(cred.id),
                  transports: cred.transports,
                })) || [],
              }
            }) as PublicKeyCredential | null
            if (!credential) throw new Error('Failed to get credential')
            const response = credential.response as AuthenticatorAssertionResponse
            ws.send(JSON.stringify({
              id: credential.id,
              rawId: b64enc(credential.rawId),
              response: {
                clientDataJSON: b64enc(response.clientDataJSON),
                authenticatorData: b64enc(response.authenticatorData),
                signature: b64enc(response.signature),
                userHandle: response.userHandle ? b64enc(response.userHandle) : null,
              },
              type: credential.type,
              clientExtensionResults: credential.getClientExtensionResults(),
              authenticatorAttachment: (credential as any).authenticatorAttachment,
            }))
            return
          }
          if (data.status === 'success') {
            ws.close()
            resolve(foundMsg)
            return
          }
        } catch (err: any) {
          ws.close()
          reject(new Error(err.message || 'Permit failed'))
        }
      }
      ws.onerror = () => reject(new Error('WebSocket error during permit'))
    })
  }, { code, powSrc: solvePoWSource, b64src: b64helpersSource })
}
